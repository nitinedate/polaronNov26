"""Pure text projection/chunk helpers for forensic RAG.

This module intentionally has no database, SQLAlchemy, Celery or GPU imports so CPU
sidecars and unit tests can reuse the exact same evidence text policy cheaply.
"""
from __future__ import annotations

import json


def chunk_text(text: str, size: int, overlap: int) -> list[str]:
    text = (text or "").strip()
    if not text:
        return []
    size = max(int(size or 1), 1)
    overlap = max(0, min(int(overlap or 0), size - 1))
    if len(text) <= size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        chunks.append(text[start:end])
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


def extract_text_from_normalized(normalized) -> str:
    """Project parser-normalized evidence into searchable prose without JSON bloat."""
    if not normalized:
        return ""
    if isinstance(normalized, str):
        return normalized
    if isinstance(normalized, list):
        parts: list[str] = []
        for rec in normalized:
            if isinstance(rec, dict):
                if rec.get("text"):
                    parts.append(str(rec["text"]))
                elif rec.get("preview"):
                    parts.append(str(rec["preview"]))
                else:
                    sub: list[str] = []
                    for key in (
                        "executable", "target", "event_id", "event_kind", "registry_key",
                        "registry_value_name", "table", "user_profile", "target_paths",
                        "username", "last_logon", "password_last_set", "last_logoff",
                        "event_time", "profile_image_path", "sid", "rid",
                        "ntuser_last_write", "profile_key_last_write", "record_type",
                        "product_name", "display_version", "current_build", "edition_id",
                        "computer_name", "install_date", "url", "device_name", "serial",
                        "message_count", "text_body", "text_preview", "path", "size_bytes",
                        "body", "sender", "recipient", "subject", "file_name", "application",
                        "conversation", "direction", "media_name", "media_path",
                    ):
                        if rec.get(key) not in (None, "", [], {}):
                            val = rec[key]
                            sub.append(
                                f"{key}: {val}"
                                if not isinstance(val, list)
                                else f"{key}: {', '.join(str(v) for v in val)}"
                            )
                    if sub:
                        parts.append("\n".join(sub))
                    else:
                        parts.append(json.dumps(rec, ensure_ascii=False, default=str))
            else:
                parts.append(str(rec))
        return "\n".join(parts)
    if isinstance(normalized, dict):
        # Common parser outputs are dicts rather than list-of-records. Prefer
        # evidentiary text/value fields and fall back to compact JSON.
        parts: list[str] = []
        for key in (
            "text", "body", "content", "preview", "text_body", "text_preview",
            "subject", "title", "url", "path", "file_name", "sender", "recipient",
            "application", "conversation", "direction", "media_name", "media_path",
        ):
            value = normalized.get(key)
            if value not in (None, "", [], {}):
                parts.append(f"{key}: {value}" if key not in {"text","body","content","preview","text_body","text_preview"} else str(value))
        if parts:
            return "\n".join(parts)
        return json.dumps(normalized, ensure_ascii=False, default=str, separators=(",", ":"))
    return json.dumps(normalized, ensure_ascii=False, default=str)


def unique_text_plan(texts: list[str]) -> tuple[list[str], list[int]]:
    """Return unique texts and a stable position map without changing evidence rows.

    Embedding identical chunk text once is lossless: every original chunk is still
    persisted with its own path/provenance, but duplicate content reuses the same
    vector. This is especially valuable for repeated email footers, templates,
    copied documents and duplicated chat attachments.
    """
    unique: list[str] = []
    positions: list[int] = []
    seen: dict[str, int] = {}
    for raw in texts:
        text = str(raw or "")
        idx = seen.get(text)
        if idx is None:
            idx = len(unique)
            seen[text] = idx
            unique.append(text)
        positions.append(idx)
    return unique, positions


def expand_unique_values(values: list, positions: list[int]) -> list:
    """Expand values aligned to ``unique_text_plan`` back to source order."""
    return [values[pos] for pos in positions]
