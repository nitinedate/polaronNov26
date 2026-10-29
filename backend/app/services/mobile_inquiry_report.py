"""Read-only mobile report inquiry evidence. Never infer guilt or prove absence.

The language model can polish the separately generated observation prose, but
this deterministic appendix preserves source paths and case-scoped retrieval.
"""
from __future__ import annotations

import re
from app.db.sql_helpers import fetchall

QUESTIONS = (
    ("Offer letters and employment correspondence", ("offer letter", "appointment letter", "job offer", "interview", "recruitment", "employment", "resignation")),
    ("Chats and external communications", ("whatsapp", "telegram", "signal", "chat", "email", "forwarded", "shared")),
    ("Images, documents, videos and audio", ("screenshot", "handwritten", "photograph", "image", "video", "voice note", "document")),
    ("Unusual activity and potential data transfers", ("uploaded", "external drive", "transfer", "deleted", "cloud storage", "shared link", "confidential")),
)


def _clean(value: object, limit: int = 250) -> str:
    return re.sub(r"[\r\n\t|]+", " ", str(value or "")).strip()[:limit]


def build_mobile_inquiry_findings(db, job_id: str, intake: dict, *, limit_per_question: int = 5) -> str:
    """Return reproducible leads from the *current job only* with citations.

    Search hits are candidate leads for human review, not verified findings.
    """
    lines = ["### 4. Intake-driven examination questions", "",
             "The following are potential leads from the accessible indexed evidence, not proof of misconduct. "
             "A negative search does not establish that an event did not occur. Each lead requires examiner verification.", ""]
    background = _clean(intake.get("background") or intake.get("incident_summary"), 800)
    if background:
        lines += ["**Case context supplied at intake:** " + background, ""]
    for heading, terms in QUESTIONS:
        lines += ["#### " + heading, ""]
        clauses = " OR ".join(f"(file_path ILIKE :t{i} OR content ILIKE :t{i})" for i in range(len(terms)))
        params = {"jid": job_id, "lim": max(1, min(int(limit_per_question), 15))}
        params.update({f"t{i}": "%" + term + "%" for i, term in enumerate(terms)})
        # Deliberately bounded to avoid report-generation table scans without limit.
        rows = fetchall(db, f"""SELECT file_path, LEFT(COALESCE(content,''), 400) AS content
            FROM rag_chunks WHERE job_id=CAST(:jid AS uuid) AND ({clauses})
            ORDER BY created_at DESC NULLS LAST LIMIT :lim""", params) or []
        if rows:
            lines.append(f"{len(rows)} candidate source(s) surfaced for manual review (limited search sample):")
            for row in rows:
                path = _clean(row.get("file_path"), 320)
                preview = _clean(row.get("content"), 170)
                # Source path is a file-level citation; do not quote unreviewed text as a conclusion.
                lines.append(f"- Source: `{path}` — excerpt: {preview or '[indexed content unavailable]'}")
        else:
            lines.append("No matching readable indexed records were identified by this limited query. Not established; review acquisition coverage and unavailable sources.")
        lines.append("")
    lines += ["**Scope limitation:** Encrypted private-app data, missing keys, unavailable cloud accounts, unsupported files, failed OCR and overwritten artifacts may contain information not represented in these searches.", ""]
    return "\n".join(lines)
