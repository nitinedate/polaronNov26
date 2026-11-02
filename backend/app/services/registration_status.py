"""Read-only, source-scoped verification of committed EWF registration."""

from pathlib import Path


def registration_snapshot(rows: list[dict], folder: str, expected_names: list[str]) -> dict:
    """Never count the same-named segments registered under a different directory."""
    folder_key = str(folder).replace("\\", "/").rstrip("/").casefold()
    scoped: list[dict] = []
    for row in rows:
        host = str(row.get("host_path") or "").replace("\\", "/")
        if not host:
            continue
        parent = str(Path(host).parent).rstrip("/").casefold()
        if parent == folder_key or parent.startswith(folder_key + "/"):
            scoped.append(row)
    known = {str(row.get("original_name") or "").casefold() for row in scoped}
    expected = list(dict.fromkeys(name.strip() for name in expected_names if name.strip()))
    missing = [name for name in expected if name.casefold() not in known]
    # Without a source-file list, a partial registration is not proven complete.
    # The caller may still use the successful ingest-path POST acknowledgement.
    complete = bool(expected) and not missing
    return {
        "complete": complete, "registered_count": len(scoped),
        "expected_count": len(expected), "missing_names": missing,
    }
