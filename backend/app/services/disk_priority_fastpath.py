"""Conservative disk-only priority-pass acceleration.

Do not touch mobile parsing. Acquired objects remain immutable and indexed in
job_artifacts. 'safe_deferred' means no assertion about an unexamined header.
The full signature path remains available via DISK_PRIORITY_SIGNATURE_MODE=full.
"""
from __future__ import annotations

from pathlib import PurePosixPath

# Only well-known operating-system binary/resource extensions, and only inside
# OS installation trees. Never defer user documents, mail, browser databases,
# chat sources, registry transaction files, carved/deleted content or unknown DBs.
_OS_BINARY_EXTS = frozenset({
    ".dll", ".sys", ".mui", ".cat", ".mum", ".manifest", ".admx",
    ".adml", ".ocx", ".tlb", ".cpl", ".efi",
})
_OS_PREFIXES = (
    "/windows/system32/", "/windows/syswow64/", "/windows/winsxs/",
    "/windows/servicing/", "/windows/assembly/", "/windows/policydefinitions/",
)
_PRIORITY_HINTS = (
    "/users/", "/documents and settings/", "/downloads/", "/desktop/",
    "/temp/", "/tmp/", "/recovered/", "/deleted/", "/$recycle.bin/",
    "/programdata/", "/appdata/", "unallocated", "carved", "quarantine",
)


def can_defer_fallback_signature(item, parsers, bundle, *, mode: str,
                                  web_text: bool, storage: bool) -> bool:
    """Only metadata-only classification on unmistakable system path/extension.

    Reversible via clearing the priority_parsed_v4 marker for selected sources,
    then running with DISK_PRIORITY_SIGNATURE_MODE=full.
    """
    if mode != "safe_deferred" or web_text or storage or len(bundle) != 1:
        return False
    if len(parsers) != 1 or getattr(parsers[0], "name", "") != "forensic_fallback":
        return False
    # Acquired paths are "Windows/WinSxS/..." with no drive letter and often no
    # leading slash. Prefixes are written as "/windows/winsxs/", so normalize
    # once or those OS binaries never match and each one reopens its shard.
    path = (item.path or "").replace("\\", "/").lower()
    if not path.startswith("/"):
        path = "/" + path
    ext = (item.extension or PurePosixPath(path).suffix or "").lower()
    if ext not in _OS_BINARY_EXTS:
        return False
    if not any(prefix in path for prefix in _OS_PREFIXES):
        return False
    if any(hint in path for hint in _PRIORITY_HINTS):
        return False
    meta = item.meta if isinstance(item.meta, dict) else {}
    if any(meta.get(k) for k in ("is_deleted", "recovered", "carved", "is_unallocated")):
        return False
    return True


def deferred_signature_artifact(item, context):
    """Keep the same deterministic fallback source ID with an honest limitation."""
    from app.services.mobile_forensic.models import NormalizedArtifact

    meta = item.meta if isinstance(item.meta, dict) else {}
    ext = (item.extension or PurePosixPath(item.path).suffix or "").lower()
    data = {
        "path": item.path,
        "name": PurePosixPath(item.path.replace("\\", "/")).name,
        "size": item.size,
        "sha256": item.sha256,
        "extension": ext,
        "mime_hint": item.mime_hint,
        "source_metadata": {
            k: v for k, v in meta.items()
            if k in ("detected_mime", "is_deleted", "inode", "file_offset")
        },
        "recognition": "signature_not_examined",
        "examination_status": "signature_deferred_os_resource",
        "signature_examination_pending": True,
        "reference_only": True,
    }
    return NormalizedArtifact.create(
        artifact_type="unclassified_file", source_domain="files", data=data,
        state="unsupported", recovery_source="acquired_file", source_path=item.path,
        source_sha256=item.sha256, parser="forensic_fallback", parser_version="1.0.0",
        job_id=context.job_id, source_id=context.source_id,
    )


def shard_stream_budget(item, parsers, *, web_text: bool = False) -> int | None:
    """Limit full-source in-memory streaming to 16 MiB per selected file.

    Only data-dependent parsers benefit. A fallback alone can use a 4 KiB
    prefix, unless parsing EML/EMLX/MBOX which requires complete message bytes.
    Sidecars are excluded by the caller; SQLite companion joining remains in
    the original reader.
    """
    names = {getattr(p, "name", "") for p in parsers}
    ext = (item.extension or PurePosixPath(item.path).suffix or "").lower()
    if ext in {".eml", ".emlx", ".mbox"}:
        return 16 * 1024 * 1024 if int(item.size or 0) <= 16 * 1024 * 1024 else None
    if names <= {"forensic_fallback", "files_media_parser"} and not web_text:
        return None
    length = int(item.size or 0)
    # Zero/unknown lengths cannot prove a byte buffer is a complete source.
    if 0 < length <= 16 * 1024 * 1024:
        return length
    return None
