"""Case exhibits for the report: offer-letter files and voice-note locations.

Searches the job's indexed evidence only. A text hit is a candidate exhibit,
not a finding that the document is an accepted offer.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from app.db.sql_helpers import fetchall

OFFER_QUESTION = (
    "Which acquired documents or images contain an offer letter or appointment letter? "
    "Each matching file is captured in Evidences with its full path and the date of the file."
)

_OFFER_RE = re.compile(
    r"offer\s+letter|appointment\s+letter|letter\s+of\s+(?:offer|appointment)",
    re.IGNORECASE,
)
_FILE_RE = re.compile(r"\.(?:pdf|docx?|jpe?g|png|webp|gif|bmp|tiff?|heic)$", re.IGNORECASE)
_PTT_DATE_RE = re.compile(r"PTT-(\d{4})(\d{2})(\d{2})", re.IGNORECASE)
_IMAGE_RE = re.compile(r"\.(?:jpe?g|png|webp|gif|bmp|tiff?|heic)$", re.IGNORECASE)


def _excerpt(content: str) -> str:
    text = re.sub(r"\s+", " ", content or "").strip()
    match = _OFFER_RE.search(text)
    if not match:
        return text[:180]
    start = max(0, match.start() - 80)
    end = min(len(text), match.end() + 80)
    return text[start:end].strip()


def _occurred_at(path: str) -> str | None:
    match = _PTT_DATE_RE.search(path or "")
    if not match:
        return None
    year, month, day = match.group(1), match.group(2), match.group(3)
    if not (1 <= int(month) <= 12 and 1 <= int(day) <= 31):
        return None
    return f"{day}/{month}/{year}"


def _voice_folder(path: str) -> str:
    norm = (path or "").replace("\\", "/")
    marker = "/WhatsApp Voice Notes"
    index = norm.lower().find(marker.lower())
    if index >= 0:
        return norm[: index + len(marker)]
    return norm.rsplit("/", 1)[0]


def offer_letter_exhibits(db, job_id: str, *, limit: int = 12) -> list[dict]:
    """Documents and images whose indexed text contains an offer or appointment letter."""
    rows = fetchall(
        db,
        """SELECT file_path, artifact_id::text AS artifact_id, LEFT(COALESCE(content, ''), 4000) AS content
           FROM rag_chunks
           WHERE job_id = CAST(:jid AS uuid)
             AND content ~* 'offer[[:space:]]+letter|appointment[[:space:]]+letter|letter[[:space:]]+of[[:space:]]+(offer|appointment)'
             AND file_path NOT LIKE '\\_\\_forensic\\_\\_%' ESCAPE '\\'
             AND file_path ~* '\\.(pdf|docx?|jpe?g|png|webp|gif|bmp|tiff?|heic)$'
           ORDER BY file_path
           LIMIT 80""",
        {"jid": job_id},
    ) or []
    chosen: dict[str, dict] = {}
    for row in rows:
        path = str(row.get("file_path") or "").strip()
        if not path or path in chosen or not _FILE_RE.search(path):
            continue
        chosen[path] = row
        if len(chosen) >= limit:
            break
    if not chosen:
        return []

    binds = {f"p{i}": path for i, path in enumerate(chosen)}
    in_sql = ", ".join(f":p{i}" for i in range(len(chosen)))
    artifacts = fetchall(
        db,
        f"""SELECT id::text AS id, file_path, file_name, extension
            FROM job_artifacts
            WHERE job_id = CAST(:jid AS uuid) AND file_path IN ({in_sql})""",
        {"jid": job_id, **binds},
    ) or []
    by_path = {str(item.get("file_path") or ""): item for item in artifacts}

    exhibits = []
    for path, row in chosen.items():
        art = by_path.get(path) or {}
        name = str(art.get("file_name") or PurePosixPath(path.replace("\\", "/")).name or "Evidence file")
        extension = str(art.get("extension") or PurePosixPath(name).suffix or "")
        kind = "image" if _IMAGE_RE.search(extension or name) else "document"
        exhibits.append(
            {
                "file_path": path,
                "file_name": name,
                "kind": kind,
                "artifact_id": str(art.get("id") or row.get("artifact_id") or "") or None,
                "occurred_at": _occurred_at(path),
                "excerpt": _excerpt(str(row.get("content") or "")),
            }
        )
    return exhibits


def voice_note_locations(db, job_id: str, *, sample: int = 8) -> dict:
    """Full folder and file paths for acquired WhatsApp voice notes."""
    rows = fetchall(
        db,
        """SELECT DISTINCT file_path
           FROM rag_chunks
           WHERE job_id = CAST(:jid AS uuid)
             AND replace(file_path, '\\', '/') ILIKE '%/WhatsApp Voice Notes/%'
           ORDER BY file_path
           LIMIT 400""",
        {"jid": job_id},
    ) or []
    paths = [str(row.get("file_path") or "").strip() for row in rows if str(row.get("file_path") or "").strip()]
    if not paths:
        return {"count": 0, "folder": "", "files": []}
    folders: dict[str, int] = {}
    for path in paths:
        folder = _voice_folder(path)
        folders[folder] = folders.get(folder, 0) + 1
    folder = max(folders, key=folders.get)
    files = []
    for path in paths:
        if _voice_folder(path) != folder:
            continue
        files.append(
            {
                "file_path": path,
                "file_name": PurePosixPath(path.replace("\\", "/")).name,
                "occurred_at": _occurred_at(path),
            }
        )
        if len(files) >= sample:
            break
    return {"count": len(paths), "folder": folder, "files": files}


def voice_note_observation_lines(db, job_id: str) -> list[str]:
    located = voice_note_locations(db, job_id)
    if not located.get("folder"):
        return []
    lines = [
        "Complete location of these voice notes:",
        str(located["folder"]),
        f"{int(located.get('count') or 0)} voice-note file(s) are stored in that folder.",
    ]
    shown = located.get("files") or []
    if shown:
        lines.append("Files that can be opened from that location:")
        for item in shown:
            when = item.get("occurred_at") or "Date not recorded on the file name"
            lines.append(f"{item.get('file_path')} — {when}")
        remaining = int(located.get("count") or 0) - len(shown)
        if remaining > 0:
            lines.append(f"{remaining} further voice-note file(s) are in the same folder.")
    return lines


def case_exhibits(db, job_id: str) -> dict:
    return {
        "offer_question": OFFER_QUESTION,
        "offer_letters": offer_letter_exhibits(db, job_id),
        "voice_notes": voice_note_locations(db, job_id),
    }
