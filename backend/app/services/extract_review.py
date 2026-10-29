"""Examiner review of the extraction plan, before any file content is read.

When ``disk_source.extract_review.required`` is set, extraction stops after the
file system has been listed and the automatic noise rules have run, and shows
the examiner where the remaining bytes are (folders and very large files). The
examiner unticks what is not evidence (a game library, a VM folder, a backup
dump) and continues. Only file-system metadata has been read at that point, so
for evidence on the examiner's own computer nothing excluded is ever uploaded.

Rules
-----
* Nothing on the evidence is deleted or modified; exclusions only stop reading.
* A named artifact (registry hive, event log, browser history, …) inside an
  excluded folder is still extracted unless the examiner excluded that exact
  file - the same guarantee the automatic noise rules give.
* Every decision is logged with who, when, which paths and how much was left
  out, and the counts go into the extraction filter statistics for the report.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Iterable

log = logging.getLogger(__name__)

REVIEW_KEY = "extract_review"
PAUSE_MESSAGE = "Waiting for examiner review: choose folders to leave out, then continue extraction"
MAX_FOLDERS = 400
MAX_BIG_FILES = 40
BIG_FILE_BYTES = 1 << 30
MAX_EXCLUSIONS = 1000


def _norm(path: str) -> str:
    return (path or "").replace("\\", "/").strip().strip("/").lower()


def state(disk_source: dict | None) -> dict[str, Any]:
    st = (disk_source or {}).get(REVIEW_KEY) if isinstance(disk_source, dict) else None
    return dict(st) if isinstance(st, dict) else {}


# Artifact locations kept even inside a folder the examiner leaves out. The OS scope
# pack marks some of them only as a *broad* claim (it collects the whole folder), e.g.
# event logs, so "specific" claims alone would not protect them.
PROTECTED_ARTIFACT_TREES: tuple[str, ...] = (
    "windows/system32/winevt/logs/",
    "windows/system32/config/",
    "windows/system32/tasks/",
    "windows/tasks/",
    "windows/system32/wbem/repository/",
    "windows/system32/logfiles/",
    "windows/system32/sru/",
    "windows/appcompat/",
    "windows/prefetch/",
    "windows/inf/setupapi",
)


def _named_artifact(path: str, os_family: str | None) -> bool:
    p = _norm(path)
    padded = "/" + p
    if any(("/" + tree) in padded for tree in PROTECTED_ARTIFACT_TREES):
        return True
    try:
        from app.services.extract_filters import FORENSIC_BROWSER_DB_NAMES

        if PurePosixPath(p).name in FORENSIC_BROWSER_DB_NAMES:
            return True
    except Exception:
        pass
    try:
        from app.services.os_artifact_scope import scope_claim_strength

        return scope_claim_strength(p, os_family=os_family, name=PurePosixPath(p).name) == "specific"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Summary shown to the examiner
# ---------------------------------------------------------------------------

def summarize(
    nodes: list[dict],
    *,
    all_nodes: list[dict] | None = None,
    filter_stats: dict | None = None,
    max_folders: int = MAX_FOLDERS,
) -> dict[str, Any]:
    """Where the bytes that would be read are: folders (depth <= 4) and very large files."""
    total_bytes = 0
    folders: dict[str, dict[str, Any]] = {}
    big: list[tuple[int, str]] = []
    for node in nodes:
        raw = str(node.get("path") or "").replace("\\", "/").strip("/")
        size = int(node.get("size_bytes") or 0)
        total_bytes += size
        parts = raw.split("/")
        for depth in range(1, min(len(parts), 5)):
            prefix = "/".join(parts[:depth])
            key = prefix.lower()
            entry = folders.get(key)
            if entry is None:
                entry = folders[key] = {"path": prefix, "bytes": 0, "files": 0, "depth": depth}
            entry["bytes"] += size
            entry["files"] += 1
        if size >= BIG_FILE_BYTES:
            big.append((size, raw))

    floor = max(64 * 1024 * 1024, total_bytes // 200)  # deeper folders only when they matter (>= 0.5 %)
    chosen = [f for f in folders.values() if f["depth"] <= 2 or f["bytes"] >= floor]
    if len(chosen) > max_folders:
        chosen = sorted(chosen, key=lambda f: -f["bytes"])[:max_folders]
    chosen.sort(key=lambda f: f["path"].lower())
    big.sort(reverse=True)

    auto: dict[str, Any] = {"files": int((filter_stats or {}).get("filtered_out") or 0)}
    if all_nodes is not None and all_nodes is not nodes:
        auto["bytes"] = max(0, sum(int(n.get("size_bytes") or 0) for n in all_nodes) - total_bytes)
    rules = {
        k: v for k, v in (filter_stats or {}).items()
        if isinstance(v, int) and v > 0 and k not in {"enumerated", "filtered_out", "to_extract"}
        and not k.startswith("tsk_") and not k.startswith("examiner_")
    }
    auto["rules"] = dict(sorted(rules.items(), key=lambda kv: -kv[1])[:20])
    return {
        "total_files": len(nodes),
        "total_bytes": total_bytes,
        "folders": chosen,
        "big_files": [{"path": p, "bytes": s} for s, p in big[:MAX_BIG_FILES]],
        "auto_excluded": auto,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Applying the examiner's decision
# ---------------------------------------------------------------------------

def clean_exclusions(paths: Iterable[str]) -> list[str]:
    out: list[str] = []
    for raw in paths or []:
        p = str(raw or "").replace("\\", "/").strip().strip("/")
        if not p or len(p) > 1024 or any(part in ("..", ".") for part in p.split("/")):
            continue
        if p.lower() not in {o.lower() for o in out}:
            out.append(p)
    if len(out) > MAX_EXCLUSIONS:
        raise ValueError(f"At most {MAX_EXCLUSIONS} exclusions are allowed")
    return out


def apply(nodes: list[dict], excluded: Iterable[str], *, os_family: str | None = None) -> tuple[list[dict], dict]:
    targets = [_norm(e) for e in excluded or [] if _norm(e)]
    stats = {"examiner_excluded_files": 0, "examiner_excluded_bytes": 0, "examiner_protected_artifacts": 0}
    if not targets:
        return list(nodes), stats
    kept: list[dict] = []
    for node in nodes:
        p = _norm(str(node.get("path") or ""))
        match = next((t for t in targets if p == t or p.startswith(t + "/")), None)
        if match is None:
            kept.append(node)
        elif p != match and _named_artifact(p, os_family):
            kept.append(node)  # e.g. Windows/System32/config/SYSTEM inside an excluded "Windows"
            stats["examiner_protected_artifacts"] += 1
        else:
            stats["examiner_excluded_files"] += 1
            stats["examiner_excluded_bytes"] += int(node.get("size_bytes") or 0)
    return kept, stats


# ---------------------------------------------------------------------------
# Pipeline gate (called by extraction right after the plan is ready)
# ---------------------------------------------------------------------------

def _load_ds(db, job_id: str) -> dict:
    from app.db.sql_helpers import fetchone

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    ds = row.get("disk_source") or {}
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except ValueError:
            ds = {}
    return dict(ds) if isinstance(ds, dict) else {}


def _save_ds(db, job_id: str, ds: dict) -> None:
    from app.db.sql_helpers import execute

    execute(db, "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:id",
            {"ds": json.dumps(ds), "id": job_id})


def _human(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{n} B"


def gate(
    db,
    job_id: str,
    *,
    nodes: list[dict],
    all_nodes: list[dict] | None,
    filter_stats: dict,
    os_family: str | None,
    nodes_uri: str | None = None,
    extract_mode: str | None = None,
) -> tuple[str, list[dict]]:
    """Return ("continue", nodes_to_extract) or ("pause", nodes) when review is pending."""
    ds = _load_ds(db, job_id)
    st = state(ds)
    if not st.get("required"):
        return "continue", nodes
    from app.services.disk_build_log import write_disk_log

    if st.get("status") == "approved":
        kept, stats = apply(nodes, st.get("excluded") or [], os_family=os_family)
        for key, value in stats.items():
            filter_stats[key] = value
        filter_stats["examiner_excluded_paths"] = list(st.get("excluded") or [])
        filter_stats["filtered_out"] = int(filter_stats.get("filtered_out") or 0) + stats["examiner_excluded_files"]
        if stats["examiner_excluded_files"]:
            write_disk_log(
                db, job_id,
                f"Examiner review applied — {stats['examiner_excluded_files']:,} file(s) "
                f"({_human(stats['examiner_excluded_bytes'])}) left out; "
                f"{stats['examiner_protected_artifacts']:,} named artifact(s) inside excluded folders kept",
                stage="extract", metadata={"examiner_review": stats, "excluded": st.get("excluded") or []},
            )
            db.commit()
        return "continue", kept

    from app.services.job_control import load_extraction_checkpoint, mark_job_paused, save_extraction_checkpoint

    st.update({"status": "pending", "summary": summarize(nodes, all_nodes=all_nodes, filter_stats=filter_stats),
               "requested_at": datetime.now(timezone.utc).isoformat()})
    ds[REVIEW_KEY] = st
    _save_ds(db, job_id, ds)
    if nodes_uri:
        # Keep the plan so continuing does not list the file system again
        # (for evidence on the examiner's PC that would mean re-reading it).
        cp = load_extraction_checkpoint(db, job_id) or {
            "completed_shards": [], "files_extracted": 0, "bytes_extracted": 0,
        }
        cp.update({"nodes_uri": nodes_uri, "filter_stats": filter_stats, "nodes_total": len(nodes)})
        if extract_mode:
            cp["extract_mode"] = extract_mode
        save_extraction_checkpoint(db, job_id, cp)
    summary = st["summary"]
    write_disk_log(
        db, job_id,
        f"Extraction plan ready for examiner review — {summary['total_files']:,} file(s), "
        f"{_human(summary['total_bytes'])} after automatic noise exclusion. "
        "Choose folders to leave out, then continue.",
        stage="extract", metadata={"examiner_review": "pending"},
    )
    mark_job_paused(db, job_id, message=PAUSE_MESSAGE)
    db.commit()
    return "pause", nodes
