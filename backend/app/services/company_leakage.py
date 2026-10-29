"""Resumable, evidence-linked company information leakage detection.

The detector is intentionally high-precision and review-oriented.  It never calls a
candidate a confirmed leak.  It correlates parsed document text, OCR text and the
existing image/video review output, then persists a source-linked candidate artifact
for examiner review.  No source file is modified or copied by this service.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone, retry_on_deadlock

_DOC_EXT = {".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".csv", ".txt"}
_IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp", ".tif", ".tiff"}
_VIDEO_EXT = {".mp4", ".mov", ".m4v", ".3gp", ".avi", ".mkv", ".webm"}
_CANDIDATE_EXT = _DOC_EXT | _IMAGE_EXT | _VIDEO_EXT

_CHANNEL_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("whatsapp", re.compile(r"whatsapp|com\.whatsapp|chatstorage|msgstore", re.I)),
    ("email", re.compile(r"(?:^|[/\\])(mail|email|outlook|gmail|attachments?)(?:[/\\]|$)|\.eml[/\\]|\.msg[/\\]", re.I)),
    ("teams", re.compile(r"microsoft[ ._-]?teams|[/\\]teams[/\\]", re.I)),
    ("slack", re.compile(r"[/\\]slack[/\\]|slack[_ .-]", re.I)),
    ("telegram", re.compile(r"telegram|org\.telegram", re.I)),
    ("signal", re.compile(r"signal|securesms", re.I)),
    ("discord", re.compile(r"discord", re.I)),
    ("messaging", re.compile(r"[/\\](messages?|chats?|attachments?)[/\\]", re.I)),
    ("cloud_sync", re.compile(r"onedrive|dropbox|google[ _-]?drive|sharepoint", re.I)),
)

# Strong information classes.  A hit is a candidate, not a conclusion.
_CATEGORY_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "confidential_marking": (
        re.compile(r"\bconfidential\b", re.I),
        re.compile(r"\binternal\s+(?:use|distribution)\s+only\b", re.I),
        re.compile(r"\bproprietary\b", re.I),
        re.compile(r"\btrade\s+secret\b", re.I),
        re.compile(r"\bdo\s+not\s+(?:share|distribute|forward)\b", re.I),
    ),
    "customer_or_client_data": (
        re.compile(r"\bcustomer\s+list\b", re.I), re.compile(r"\bclient\s+list\b", re.I),
        re.compile(r"\bcustomer\s+(?:data|details|records)\b", re.I),
    ),
    "commercial_or_pricing": (
        re.compile(r"\bpricing\s+(?:sheet|model|strategy)\b", re.I),
        re.compile(r"\bquotation\b", re.I), re.compile(r"\brate\s+card\b", re.I),
        re.compile(r"\bmargin\s+analysis\b", re.I),
    ),
    "financial_or_payroll": (
        re.compile(r"\bpayroll\b", re.I), re.compile(r"\bsalary\s+(?:sheet|register|details)\b", re.I),
        re.compile(r"\bfinancial\s+statement\b", re.I), re.compile(r"\bbank\s+account\b", re.I),
    ),
    "credentials_or_secrets": (
        re.compile(r"\bapi[_ -]?key\b", re.I), re.compile(r"\bprivate\s+key\b", re.I),
        re.compile(r"\bpassword\s*[:=]", re.I), re.compile(r"\bsecret\s*[:=]", re.I),
        re.compile(r"\baccess\s+token\b", re.I),
    ),
    "source_or_technical_ip": (
        re.compile(r"\bsource\s+code\b", re.I), re.compile(r"\barchitecture\s+(?:diagram|document)\b", re.I),
        re.compile(r"\bdesign\s+document\b", re.I), re.compile(r"\bproduct\s+roadmap\b", re.I),
    ),
    "legal_or_contractual": (
        re.compile(r"\bnon[- ]disclosure\s+agreement\b", re.I), re.compile(r"\bnda\b", re.I),
        re.compile(r"\bmaster\s+service\s+agreement\b", re.I), re.compile(r"\bstatement\s+of\s+work\b", re.I),
    ),
}


def ensure_company_leakage_schema(db) -> None:
    execute(db, """CREATE TABLE IF NOT EXISTS company_leakage_scan_state (
        job_artifact_id uuid PRIMARY KEY REFERENCES job_artifacts(id) ON DELETE CASCADE,
        job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        content_version text NOT NULL,
        status text NOT NULL DEFAULT 'checked',
        checked_at timestamptz NOT NULL DEFAULT NOW(),
        error text
    )""")
    execute(db, """CREATE TABLE IF NOT EXISTS company_leakage_evidence (
        id bigserial PRIMARY KEY,
        job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        job_artifact_id uuid NOT NULL REFERENCES job_artifacts(id) ON DELETE CASCADE,
        source_path text NOT NULL,
        source_sha256 text,
        channel text NOT NULL DEFAULT 'unknown',
        evidence_type text NOT NULL,
        risk_score smallint NOT NULL DEFAULT 0,
        confidence double precision NOT NULL DEFAULT 0,
        categories text[] NOT NULL DEFAULT ARRAY[]::text[],
        matched_terms text[] NOT NULL DEFAULT ARRAY[]::text[],
        detection_methods text[] NOT NULL DEFAULT ARRAY[]::text[],
        excerpt text,
        details jsonb NOT NULL DEFAULT '{}'::jsonb,
        examiner_status text NOT NULL DEFAULT 'pending_review',
        created_at timestamptz NOT NULL DEFAULT NOW(),
        updated_at timestamptz NOT NULL DEFAULT NOW(),
        UNIQUE(job_id, job_artifact_id)
    )""")
    # Index DDL is an optimization, never a prerequisite to scanning evidence.
    # CREATE INDEX IF NOT EXISTS still waits on ShareLock when the index already
    # exists, and that waiter blocks later inserts. Skip a present index, and
    # give up quickly when a writer (for example a case delete) holds the table.
    import logging
    have = {
        str(row.get("relname") or "")
        for row in fetchall(
            db,
            """SELECT c.relname FROM pg_class c
               JOIN pg_namespace n ON n.oid=c.relnamespace
               WHERE n.nspname=current_schema() AND c.relkind='i'""",
        )
    }
    def _ensure_index(sql: str) -> None:
        name = sql.split("EXISTS", 1)[-1].strip().split()[0]
        if name in have:
            return
        try:
            with db.begin_nested():
                execute(db, "SET LOCAL lock_timeout = '8s'")
                execute(db, sql)
                execute(db, "SET LOCAL lock_timeout = '0'")
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Deferring optional company-leakage index build: %s (%s)", sql, exc
            )

    for sql in (
        "CREATE INDEX IF NOT EXISTS ix_company_leak_job_risk ON company_leakage_evidence(job_id, risk_score DESC, id)",
        "CREATE INDEX IF NOT EXISTS ix_company_leak_job_channel ON company_leakage_evidence(job_id, channel, risk_score DESC)",
        "CREATE INDEX IF NOT EXISTS ix_company_leak_job_type ON company_leakage_evidence(job_id, evidence_type, risk_score DESC)",
        "CREATE INDEX IF NOT EXISTS ix_company_leak_artifact ON company_leakage_evidence(job_artifact_id)",
        "CREATE INDEX IF NOT EXISTS ix_company_leak_categories_gin ON company_leakage_evidence USING gin(categories)",
        "CREATE INDEX IF NOT EXISTS ix_company_leak_terms_gin ON company_leakage_evidence USING gin(matched_terms)",
        "CREATE INDEX IF NOT EXISTS ix_company_leak_scan_job ON company_leakage_scan_state(job_id, checked_at, job_artifact_id)",
        # pg_trgm is part of the Polaron PostgreSQL baseline.  These make examiner
        # searches inside the new leakage artifact family responsive even at scale.
        "CREATE INDEX IF NOT EXISTS ix_company_leak_source_trgm ON company_leakage_evidence USING gin(source_path gin_trgm_ops)",
        "CREATE INDEX IF NOT EXISTS ix_company_leak_excerpt_trgm ON company_leakage_evidence USING gin(excerpt gin_trgm_ops)",
    ):
        _ensure_index(sql)


def _company_terms(db) -> list[str]:
    values: list[str] = []
    for key in ("COMPANY_LEAKAGE_TERMS", "COMPANY_NAME", "COMPANY_BRANDS"):
        raw = str(os.environ.get(key, "") or "")
        values.extend(v.strip() for v in re.split(r"[,;\n]", raw) if v.strip())
    try:
        schema = str((fetchone(db, "SELECT current_schema() AS s") or {}).get("s") or "")
        firm = fetchone(db, "SELECT name,slug FROM public.firms WHERE schema_name=:s LIMIT 1", {"s": schema})
        if firm:
            values.extend([str(firm.get("name") or "").strip(), str(firm.get("slug") or "").strip()])
    except Exception:
        pass
    # Avoid meaningless one-letter tenant slugs (e.g. tenant 'p').
    out = []
    seen = set()
    for value in values:
        value = re.sub(r"\s+", " ", value).strip()
        if len(value) < 3:
            continue
        low = value.lower()
        if low not in seen:
            seen.add(low); out.append(value)
    return out


def _channel(path: str) -> str:
    for name, rule in _CHANNEL_RULES:
        if rule.search(path or ""):
            return name
    return "other"


def _direction(path: str, metadata: dict[str, Any] | None = None) -> str:
    """Best-effort communication direction without asserting unsupported facts."""
    metadata = metadata or {}
    for key in ("direction", "message_direction", "mail_folder", "folder", "box"):
        value = str(metadata.get(key) or "").strip().lower()
        if value in {"outgoing", "sent", "sent_items", "sent items", "outbound", "from_me"}:
            return "outgoing"
        if value in {"incoming", "received", "inbox", "inbound", "to_me"}:
            return "incoming"
    low = str(path or "").lower().replace("\\", "/")
    if any(token in low for token in ("/sent/", "/sent items/", "/outgoing/", "/outbound/", "/from_me/")):
        return "outgoing"
    if any(token in low for token in ("/inbox/", "/received/", "/incoming/", "/inbound/")):
        return "incoming"
    return "unknown"


def _evidence_type(ext: str) -> str:
    ext = (ext or "").lower()
    if ext in _IMAGE_EXT: return "image"
    if ext in _VIDEO_EXT: return "video"
    return "document"


def _content_version(row: dict[str, Any], parse_meta: dict[str, Any], ocr_meta: dict[str, Any], media_meta: dict[str, Any]) -> str:
    raw = "|".join([
        str(row.get("updated_at") or ""), str(parse_meta.get("max_at") or ""), str(parse_meta.get("count") or 0),
        str(ocr_meta.get("max_at") or ""), str(ocr_meta.get("count") or 0), str(media_meta.get("updated_at") or ""),
    ])
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def _classify(text: str, *, path: str, company_terms: list[str], channel_hint: str | None = None, direction_hint: str | None = None) -> dict[str, Any] | None:
    compact = re.sub(r"\s+", " ", text or " ").strip()
    if not compact:
        return None
    categories: list[str] = []
    matched: list[str] = []
    hit_spans: list[tuple[int, int]] = []
    for category, patterns in _CATEGORY_PATTERNS.items():
        for pattern in patterns:
            m = pattern.search(compact)
            if m:
                categories.append(category); matched.append(m.group(0)); hit_spans.append(m.span()); break
    company_hits: list[str] = []
    low = compact.lower()
    for term in company_terms:
        if term.lower() in low:
            company_hits.append(term)
    shared_channel = str(channel_hint or _channel(path) or "other").lower()
    direction = str(direction_hint or "unknown").lower()
    shared = shared_channel != "other" or direction == "outgoing"
    # High-precision scoring: shared context + sensitive class, or company identity + strong sensitive class.
    score = 0
    if categories: score += min(45 + 8 * (len(set(categories)) - 1), 70)
    if company_hits: score += 20
    if shared: score += 20
    if direction == "outgoing": score += 15
    if any(x in path.lower() for x in ("attach", "sent", "outgoing", "shared", "whatsapp media")): score += 10
    if not categories and company_hits and shared: score = max(score, 55)
    threshold = max(40, min(int(os.environ.get("COMPANY_LEAKAGE_MIN_SCORE", "55") or 55), 95))
    if score < threshold:
        return None
    start = max(0, (hit_spans[0][0] if hit_spans else low.find(company_hits[0].lower()) if company_hits else 0) - 180)
    excerpt = compact[start:start + 900]
    confidence = min(0.99, 0.45 + score / 180.0)
    return {
        "risk_score": min(score, 100), "confidence": round(confidence, 3),
        "categories": sorted(set(categories or ["company_information"])),
        "matched_terms": sorted(set(matched + company_hits), key=str.lower),
        "channel": shared_channel, "direction": direction, "excerpt": excerpt,
    }


def run_company_leakage_analysis(db, job_id: str, *, batch_size: int = 500, max_batches: int | None = None) -> dict[str, Any]:
    """Incrementally scan all document/image/video evidence using existing derived text.

    Re-running is cheap: a content-version state row prevents unchanged artifacts from
    being rescanned.  New OCR/media-review output changes the version and causes only
    those artifacts to be reconsidered.
    """
    ensure_company_leakage_schema(db)
    company_terms = _company_terms(db)
    exts = sorted(_CANDIDATE_EXT)
    total_checked = total_flagged = 0
    batches = 0
    last_id = "00000000-0000-0000-0000-000000000000"
    while True:
        rows = fetchall(db, """SELECT ja.id,ja.file_path,ja.file_name,ja.extension,ja.sha256,ja.updated_at,ja.metadata,
                    s.content_version AS prior_version
             FROM job_artifacts ja
             LEFT JOIN company_leakage_scan_state s ON s.job_artifact_id=ja.id
             WHERE ja.job_id=:jid AND ja.id>:last
               AND lower(CASE WHEN left(coalesce(ja.extension,''),1)='.' THEN ja.extension ELSE '.'||coalesce(ja.extension,'') END)=ANY(:exts)
             ORDER BY ja.id LIMIT :lim""", {"jid": job_id, "last": last_id, "exts": exts, "lim": max(50, min(int(batch_size), 2000))})
        if not rows:
            break
        ids = [str(r["id"]) for r in rows]
        parse_rows = fetchall(db, """SELECT job_artifact_id,count(*)::int AS count,max(created_at) AS max_at,
                    left(string_agg(left(normalized::text,50000), E'\\n'),1000000) AS text
             FROM artifact_parse_results WHERE job_artifact_id=ANY(CAST(:ids AS uuid[])) GROUP BY job_artifact_id""", {"ids": ids})
        ocr_rows = fetchall(db, """SELECT job_artifact_id,count(*)::int AS count,max(created_at) AS max_at,
                    left(string_agg(left(ocr_text,100000), E'\\n'),1000000) AS text
             FROM ocr_results WHERE job_artifact_id=ANY(CAST(:ids AS uuid[])) GROUP BY job_artifact_id""", {"ids": ids})
        media_rows = []
        try:
            media_rows = fetchall(db, """SELECT job_artifact_id,updated_at,description,details
                FROM forensic_media_observations WHERE job_artifact_id=ANY(CAST(:ids AS uuid[]))""", {"ids": ids})
        except Exception:
            try: db.rollback()
            except Exception: pass
        pmap = {str(r["job_artifact_id"]): r for r in parse_rows}
        omap = {str(r["job_artifact_id"]): r for r in ocr_rows}
        mmap = {str(r["job_artifact_id"]): r for r in media_rows}
        # One batched lookup links WhatsApp/chat attachments back to their message
        # direction/sender when the mobile normalized evidence table is present.
        comm_by_name: dict[str, dict[str, Any]] = {}
        try:
            names = sorted({str(r.get("file_name") or "").strip().lower() for r in rows if r.get("file_name")})
            if names and (fetchone(db, "SELECT to_regclass('mobile_normalized_artifacts') AS t") or {}).get("t"):
                comm_rows = fetchall(db, """SELECT DISTINCT ON (lower(data->>'media_name'))
                        lower(data->>'media_name') AS media_name, data->>'application' AS application,
                        data->>'direction' AS direction, data->>'sender' AS sender,
                        coalesce(data->>'conversation',data->>'chat',data->>'chat_jid') AS conversation,
                        timestamp_utc
                    FROM mobile_normalized_artifacts
                    WHERE job_id=:jid AND artifact_type='app_message'
                      AND lower(coalesce(data->>'media_name',''))=ANY(CAST(:names AS text[]))
                    ORDER BY lower(data->>'media_name'), timestamp_utc DESC NULLS LAST""",
                    {"jid":job_id,"names":names})
                comm_by_name = {str(r.get("media_name") or "").lower(): r for r in comm_rows}
        except Exception:
            try: db.rollback()
            except Exception: pass
        advanced = 0
        for row in rows:
            aid = str(row["id"]); p = pmap.get(aid, {}); o = omap.get(aid, {}); m = mmap.get(aid, {})
            version = _content_version(row, p, o, m)
            if row.get("prior_version") == version:
                continue
            text = "\n".join(str(x or "") for x in (p.get("text"), o.get("text"), m.get("description"), json.dumps(m.get("details") or {}, ensure_ascii=False)))
            comm = comm_by_name.get(str(row.get("file_name") or "").strip().lower(), {})
            comm_app = str(comm.get("application") or "").lower()
            channel_hint = "whatsapp" if comm_app == "whatsapp" else (comm_app if comm_app in {"telegram","signal","slack","teams","discord","email"} else None)
            direction = str(comm.get("direction") or _direction(str(row.get("file_path") or ""), row.get("metadata") if isinstance(row.get("metadata"),dict) else {}) or "unknown")
            result = _classify(text, path=str(row.get("file_path") or ""), company_terms=company_terms, channel_hint=channel_hint, direction_hint=direction)
            flagged = bool(result)

            def _persist_one() -> None:
                execute(db, """INSERT INTO company_leakage_scan_state(job_artifact_id,job_id,content_version,status,checked_at,error)
                    VALUES(:aid,:jid,:v,'checked',NOW(),NULL)
                    ON CONFLICT(job_artifact_id) DO UPDATE SET content_version=EXCLUDED.content_version,status='checked',checked_at=NOW(),error=NULL""",
                    {"aid": aid, "jid": job_id, "v": version})
                if result:
                    methods = []
                    if p.get("text"): methods.append("native_parser")
                    if o.get("text"): methods.append("ocr")
                    if m.get("description"): methods.append("visual_review")
                    execute(db, """INSERT INTO company_leakage_evidence
                        (job_id,job_artifact_id,source_path,source_sha256,channel,evidence_type,risk_score,confidence,categories,matched_terms,detection_methods,excerpt,details,updated_at)
                        VALUES(:jid,:aid,:path,:sha,:channel,:etype,:risk,:conf,:cats,:terms,:methods,:excerpt,CAST(:details AS jsonb),NOW())
                        ON CONFLICT(job_id,job_artifact_id) DO UPDATE SET channel=EXCLUDED.channel,evidence_type=EXCLUDED.evidence_type,
                        risk_score=EXCLUDED.risk_score,confidence=EXCLUDED.confidence,categories=EXCLUDED.categories,matched_terms=EXCLUDED.matched_terms,
                        detection_methods=EXCLUDED.detection_methods,excerpt=EXCLUDED.excerpt,details=EXCLUDED.details,updated_at=NOW()""",
                        {"jid":job_id,"aid":aid,"path":row.get("file_path") or "","sha":row.get("sha256"),"channel":result["channel"],"etype":_evidence_type(str(row.get("extension") or "")),"risk":result["risk_score"],"conf":result["confidence"],"cats":result["categories"],"terms":result["matched_terms"],"methods":methods,"excerpt":result["excerpt"],"details":json.dumps({"candidate_not_conclusion":True,"company_terms_configured":company_terms,"source_file_name":row.get("file_name"),"direction":direction,"sender":comm.get("sender"),"conversation":comm.get("conversation"),"message_timestamp":str(comm.get("timestamp_utc") or "") or None},ensure_ascii=False)})
                    execute(db, """UPDATE job_artifacts SET metadata=coalesce(metadata,'{}'::jsonb) ||
                        jsonb_build_object('company_leakage_candidate',true,'company_leakage_risk',CAST(:risk AS int),'company_leakage_channel',CAST(:channel AS text),'company_leakage_direction',CAST(:direction AS text)), updated_at=NOW() WHERE id=:aid""",
                        {"aid":aid,"risk":result["risk_score"],"channel":result["channel"],"direction":direction})
                else:
                    execute(db, "DELETE FROM company_leakage_evidence WHERE job_id=:jid AND job_artifact_id=:aid", {"jid":job_id,"aid":aid})
                    execute(db, "UPDATE job_artifacts SET metadata=coalesce(metadata,'{}'::jsonb)-'company_leakage_candidate'-'company_leakage_risk'-'company_leakage_channel'-'company_leakage_direction' WHERE id=:aid", {"aid":aid})

            retry_on_deadlock(db, _persist_one)
            db.commit()
            if flagged:
                total_flagged += 1
            total_checked += 1; advanced += 1
        db.commit(); batches += 1
        last_id = str(rows[-1]["id"])
        if max_batches is not None and batches >= max_batches:
            break
    count = int((fetchone(db, "SELECT count(*)::int AS c FROM company_leakage_evidence WHERE job_id=:jid", {"jid":job_id}) or {}).get("c") or 0)
    return {"status":"ok","checked":total_checked,"flagged_this_run":total_flagged,"candidate_count":count,"company_terms":company_terms}


def company_leakage_count(db, job_id: str) -> int:
    ensure_company_leakage_schema(db)
    return int((fetchone(db, "SELECT count(*)::int AS c FROM company_leakage_evidence WHERE job_id=:jid", {"jid":job_id}) or {}).get("c") or 0)


def list_company_leakage_evidence(db, job_id: str, *, page: int = 1, page_size: int = 50, q: str | None = None) -> dict[str, Any]:
    ensure_company_leakage_schema(db)
    page=max(1,int(page)); page_size=max(1,min(int(page_size),200)); offset=(page-1)*page_size
    params: dict[str, Any]={"jid":job_id,"lim":page_size,"off":offset}
    where="WHERE e.job_id=:jid"
    if q:
        where += " AND (e.source_path ILIKE :q OR e.excerpt ILIKE :q OR array_to_string(e.matched_terms,' ') ILIKE :q)"; params["q"]="%"+q+"%"
    total=int((fetchone(db,f"SELECT count(*)::int AS c FROM company_leakage_evidence e {where}",params) or {}).get("c") or 0)
    rows=fetchall(db,f"""SELECT e.*,ja.file_name,ja.extension,ja.size_bytes,ja.minio_uri,ja.created_at
        FROM company_leakage_evidence e JOIN job_artifacts ja ON ja.id=e.job_artifact_id
        {where} ORDER BY e.risk_score DESC,e.id DESC LIMIT :lim OFFSET :off""",params)
    items=[]
    for r in rows:
        details=r.get("details") or {}
        if not isinstance(details,dict): details={}
        meta={"evidence_kind":"company_information_leakage","risk_score":int(r.get("risk_score") or 0),"confidence":float(r.get("confidence") or 0),"channel":r.get("channel"),"direction":details.get("direction") or "unknown","categories":r.get("categories") or [],"matched_terms":r.get("matched_terms") or [],"detection_methods":r.get("detection_methods") or [],"preview_body":r.get("excerpt") or "","body":r.get("excerpt") or "","candidate_not_conclusion":True,"examiner_status":r.get("examiner_status")}
        items.append({"id":f"company-leak-{r['id']}","job_id":str(r["job_id"]),"file_id":str(r["job_artifact_id"]),"parent_artifact_id":None,"artifact_type":"company_information_leakage","axiom_category":"company_leakage","axiom_category_label":"Company Information Leakage","axiom_sub_category":r.get("channel"),"title":f"{r.get('file_name') or r.get('source_path')} — risk {int(r.get('risk_score') or 0)}","file_name":r.get("file_name"),"source_path":r.get("source_path"),"size_bytes":r.get("size_bytes"),"extension":r.get("extension"),"artifact_datetime":None,"preview_uri":None,"storage_uri":r.get("minio_uri"),"metadata":meta,"tags":["company_leakage","pending_review"],"examiner_comment":"Candidate company-information disclosure; examiner confirmation required.","parser_version":"company-leakage-v1","confidence":float(r.get("confidence") or 0),"created_at":r.get("created_at").isoformat() if hasattr(r.get("created_at"),"isoformat") else str(r.get("created_at") or "")})
    return {"items":items,"total":total,"page":page,"page_size":page_size,"evidence_domain":"company_leakage","evidence_label":"Company Information Leakage","group_by":None,"group_id":None,"message_filter":"all","thread_summary":None}
