import json
from collections import defaultdict
from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.disk_manifest import load_index_entries
import zstandard as zstd
from app.services.storage import get_bytes

JOB = "abf989c4-83c4-4bc3-af1d-5c617410b6d9"
db = SessionLocal()
db.execute(text('SET search_path TO firm_p, public'))
row = db.execute(text("SELECT disk_source FROM jobs WHERE id=:id"), {"id": JOB}).mappings().first()
manifest = row["disk_source"] or {}

def load_uri(uri):
    raw = get_bytes(uri)
    data = zstd.ZstdDecompressor().decompress(raw)
    return [json.loads(line) for line in data.decode("utf-8", errors="replace").splitlines() if line.strip()]

combined = load_uri(manifest["index_uri"])
print("combined", len(combined))
by = defaultdict(list)
for entry in combined:
    path = (entry.get("path") or "").replace("\\", "/")
    by[path].append(entry)
dups = {p: rows for p, rows in by.items() if len(rows) > 1}
print("combined_unique", len(by), "dup_paths", len(dups))
for path, rows in sorted(dups.items()):
    brief = []
    for entry in rows:
        brief.append({k: entry.get(k) for k in ("sha256", "size", "part_id", "offset", "bytes")})
    same = len({json.dumps(b, sort_keys=True) for b in brief}) == 1
    print(("SAME" if same else "DIFF"), len(rows), path)
    if not same:
        for b in brief:
            print("   ", b)
