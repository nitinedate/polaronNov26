#!/usr/bin/env python3
"""
whatsapp_offline_extract.py  —  Offline, read-only WhatsApp recovery for Android forensics.

PURPOSE
    Recover and decrypt WhatsApp chats from evidence you ALREADY have, WITHOUT
    touching, rooting or otherwise modifying the handset. It takes a full-file-
    system image / logical extraction / tar / adb-backup that contains WhatsApp's
    private files, pulls out the 158-byte `files/key` and the `msgstore.db.cryptNN`
    backups, decrypts them, and writes a plaintext `msgstore.db` (+ optional CSV).

WHY THIS IS THE FORENSIC PATH
    On a NON-rooted, unmodified device, `/data/data/com.whatsapp/files/key` is
    inside WhatsApp's app sandbox; Android lets only uid 0 read it. No software
    "unlocks" that without writing to the device, and rooting an unrooted phone
    alters the evidence. The defensible route is: acquire a full-file-system /
    physical image with a tool that preserves integrity (Cellebrite UFED/Physical
    Analyzer, Oxygen, MSAB XRY/XAMN, Magnet GrayKey, or your own TSK pipeline),
    then do the decryption OFFLINE from the image — which is exactly what this does.

INPUT MODES (choose one source)
    --from-dir  DIR            A directory tree (mounted image / logical pull).
    --from-tar  FILE[.tar/.gz] A tar/tgz archive of the extraction.
    --from-ab   FILE.ab        An `adb backup` file (only useful on old WhatsApp
                               where allowBackup=true; modern builds yield nothing).
    --from-image IMG           A raw ext4/F2FS partition image, read via The Sleuth
                               Kit (pytsk3) WITHOUT mounting and WITHOUT root.
                               Optional: --fs-offset BYTES for a whole-disk image.
    You may also supply pieces directly:
    --key-file FILE  --hex-key HEX  --backup FILE.cryptNN

OUTPUT
    -o OUTDIR (default ./wa_out): msgstore.db (plaintext) and, with --dump-chats,
    chats.csv / chats.json. A JSON manifest records SHA-256s and a custody line.

This mirrors the logic already in the Polaron pipeline
(backend/app/services/mobile_forensic/whatsapp_crypt.py and
backend/app/malware/whatsapp_crypt.py); it is packaged standalone so it can run
on the examiner workstation against an image with nothing but Python +
`cryptography` (+ optional `pytsk3` for --from-image).
"""
from __future__ import annotations
import argparse, hashlib, io, json, os, sys, tarfile, zlib, datetime
from pathlib import Path

HKDF_INFO = b"backup encryption"
SQLITE_MAGIC = b"SQLite format 3\x00"
KEY_BASENAMES = ("key", "encrypted_backup.key")
BACKUP_SUFFIXES = (".crypt12", ".crypt14", ".crypt15")


# ----------------------------- crypto core ---------------------------------
class WhatsAppKeyError(ValueError):
    pass


def normalise_key(key: str) -> bytes:
    raw = "".join(str(key or "").split()).lower().removeprefix("0x")
    try:
        out = bytes.fromhex(raw)
    except ValueError as exc:
        raise WhatsAppKeyError("Key must be 64 hex digits") from exc
    if len(out) != 32:
        raise WhatsAppKeyError(f"Key must be 32 bytes; got {len(out)}")
    return out


def key_from_crypt14_file(data: bytes) -> bytes:
    if not data or len(data) < 32 or len(data) > 4096:
        raise WhatsAppKeyError("Not a valid WhatsApp key file")
    return data[-32:]          # 158-byte file: AES-256 key is the final 32 bytes (offset 126)


def _gcm_key(root: bytes) -> bytes:
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=SHA256(), length=32, salt=b"", info=HKDF_INFO).derive(root)


def _pb_fields(buf: bytes):
    i = 0
    while i < len(buf):
        key = shift = 0
        while i < len(buf):
            b = buf[i]; i += 1
            key |= (b & 0x7F) << shift
            if not b & 0x80:
                break
            shift += 7
        field, wire = key >> 3, key & 7
        if wire == 2:
            ln = shift = 0
            while i < len(buf):
                b = buf[i]; i += 1
                ln |= (b & 0x7F) << shift
                if not b & 0x80:
                    break
                shift += 7
            yield field, wire, buf[i:i + ln]; i += ln
        elif wire == 0:
            while i < len(buf) and buf[i] & 0x80:
                i += 1
            i += 1; yield field, wire, None
        elif wire == 5:
            i += 4; yield field, wire, None
        elif wire == 1:
            i += 8; yield field, wire, None
        else:
            return


def _header_iv(header: bytes):
    top = {f: v for f, w, v in _pb_fields(header) if w == 2}
    if 3 in top:                                  # crypt15: c15_iv(3).IV(1)
        for f, _w, v in _pb_fields(top[3]):
            if f == 1 and v and len(v) == 16:
                return v, "crypt15"
    if 2 in top:                                  # crypt14: c14_cipher(2).IV(5)
        for f, _w, v in _pb_fields(top[2]):
            if f == 5 and v and len(v) == 16:
                return v, "crypt14"
    return None, None


def _read_header(buf: io.BytesIO):
    size = buf.read(1)
    if not size:
        raise WhatsAppKeyError("Backup empty/truncated")
    size = size[0]
    flag = buf.read(1)
    if not (flag and flag[0] == 1) and flag:
        buf.seek(-1, io.SEEK_CUR)
    header = buf.read(size)
    iv, kind = _header_iv(header)
    if iv is None:
        raise WhatsAppKeyError("No IV in header — not a .crypt14/.crypt15 backup")
    return iv, kind


def detect_format(blob: bytes):
    try:
        return _read_header(io.BytesIO(blob[:800]))[1]
    except WhatsAppKeyError:
        return None


def _decrypt(blob: bytes, gcm_key: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    buf = io.BytesIO(blob)
    iv, _ = _read_header(buf)
    rest = buf.read()
    if len(rest) < 32:
        raise WhatsAppKeyError("Backup truncated")
    aead = AESGCM(gcm_key)
    plain = None
    for data_and_tag in (rest[:-16], rest):       # single-file (strip md5), then multi-file
        try:
            plain = aead.decrypt(iv, data_and_tag, None); break
        except InvalidTag:
            plain = None
    if plain is None:
        raise WhatsAppKeyError("Key does not match this backup (GCM auth failed)")
    try:
        plain = zlib.decompress(plain)
    except zlib.error:
        pass
    if not plain.startswith(SQLITE_MAGIC):
        raise WhatsAppKeyError("Decrypted output is not a SQLite DB; wrong key/backup")
    return plain


def decrypt_backup(blob: bytes, *, hex_key=None, key_file=None) -> bytes:
    kind = detect_format(blob)
    if kind is None:
        raise WhatsAppKeyError("Not a WhatsApp .crypt14/.crypt15 backup")
    if kind == "crypt15":
        if not hex_key and key_file:
            hex_key = key_from_crypt14_file(key_file).hex()
        if not hex_key:
            raise WhatsAppKeyError("Crypt15 needs the 64-digit key")
        return _decrypt(blob, _gcm_key(normalise_key(hex_key)))
    if key_file is not None:
        return _decrypt(blob, key_from_crypt14_file(key_file))
    if hex_key:
        return _decrypt(blob, normalise_key(hex_key))
    raise WhatsAppKeyError("Crypt14 needs the files/key file")


# ----------------------------- evidence intake ------------------------------
def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _collect_from_dir(root: Path):
    keys, backups = {}, {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.name in KEY_BASENAMES and "com.whatsapp" in str(p).replace("\\", "/"):
            keys[str(p)] = p.read_bytes()
        elif p.suffix in BACKUP_SUFFIXES and p.name.startswith("msgstore"):
            backups[str(p)] = p.read_bytes()
    # fall back: any file named exactly "key" of plausible size
    if not keys:
        for p in root.rglob("key"):
            if p.is_file() and 32 <= p.stat().st_size <= 1024:
                keys[str(p)] = p.read_bytes()
    return keys, backups


def _collect_from_tar(tf_path: Path):
    keys, backups = {}, {}
    with tarfile.open(tf_path, "r:*") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            name = m.name.replace("\\", "/")
            base = os.path.basename(name)
            if base in KEY_BASENAMES and "com.whatsapp" in name:
                keys[name] = tf.extractfile(m).read()
            elif base.startswith("msgstore") and name.endswith(BACKUP_SUFFIXES):
                backups[name] = tf.extractfile(m).read()
    return keys, backups


def _collect_from_ab(ab_path: Path):
    """Android `adb backup` (.ab): 24-byte text header + zlib stream -> tar."""
    raw = ab_path.read_bytes()
    nl = [i for i, c in enumerate(raw) if c == 0x0A]
    if len(nl) < 4 or not raw.startswith(b"ANDROID BACKUP"):
        raise WhatsAppKeyError("Not an unencrypted ADB backup (.ab) stream")
    payload = raw[nl[3] + 1:]
    tar_bytes = zlib.decompress(payload)
    keys, backups = {}, {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            name = m.name.replace("\\", "/"); base = os.path.basename(name)
            if base in KEY_BASENAMES:
                keys[name] = tf.extractfile(m).read()
            elif base.startswith("msgstore") and name.endswith(BACKUP_SUFFIXES):
                backups[name] = tf.extractfile(m).read()
    return keys, backups


def _collect_from_image(img_path: Path, fs_offset: int = 0):
    """Read the key + backups straight out of an ext4/F2FS image via The Sleuth
    Kit (pytsk3) — no mount, no loop device, no root. This is how a raw FFS image
    from a physical/FFS extraction is parsed without altering anything."""
    try:
        import pytsk3
    except ImportError as exc:
        raise WhatsAppKeyError(
            "pytsk3 not installed. `pip install pytsk3` (needs libtsk), or extract "
            "the files first and use --from-dir/--from-tar.") from exc
    keys, backups = {}, {}
    img = pytsk3.Img_Info(str(img_path))
    fs = pytsk3.FS_Info(img, offset=fs_offset)
    targets = [
        "/data/data/com.whatsapp/files/key",
        "/data/user/0/com.whatsapp/files/key",
        "/data/data/com.whatsapp/files/encrypted_backup.key",
    ]
    for t in targets:
        try:
            f = fs.open(t)
            data = f.read_random(0, f.info.meta.size)
            if 32 <= len(data) <= 1024:
                keys[t] = data
        except Exception:
            pass
    # walk the public Databases dirs for msgstore backups
    for d in ("/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
              "/sdcard/WhatsApp/Databases",
              "/data/media/0/WhatsApp/Databases"):
        try:
            for entry in fs.open_dir(d):
                nm = entry.info.name.name.decode("utf-8", "replace")
                if nm.startswith("msgstore") and nm.endswith(BACKUP_SUFFIXES):
                    f = fs.open(d + "/" + nm)
                    backups[d + "/" + nm] = f.read_random(0, f.info.meta.size)
        except Exception:
            pass
    return keys, backups


# ----------------------------- chat dump -----------------------------------
def dump_chats(db_path: Path, outdir: Path):
    import sqlite3, csv
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    # Schema differs across WhatsApp versions; try the modern layout, then legacy.
    queries = [
        """SELECT c.subject AS chat, m.from_me AS from_me, m.timestamp AS ts, m.text_data AS body
             FROM message m JOIN chat ch ON m.chat_row_id=ch._id
             LEFT JOIN jid c ON ch.jid_row_id=c._id ORDER BY m.timestamp""",
        """SELECT key_remote_jid AS chat, key_from_me AS from_me, timestamp AS ts, data AS body
             FROM messages ORDER BY timestamp""",
    ]
    rows = None
    for q in queries:
        try:
            rows = con.execute(q).fetchall(); break
        except sqlite3.Error:
            rows = None
    con.close()
    if rows is None:
        return 0
    recs = []
    for r in rows:
        ts = r["ts"]
        try:
            when = datetime.datetime.fromtimestamp(int(ts) / 1000, datetime.timezone.utc).isoformat() if ts else ""
        except Exception:
            when = str(ts)
        recs.append({"chat": r["chat"], "direction": "sent" if r["from_me"] else "received",
                     "timestamp_utc": when, "body": r["body"]})
    (outdir / "chats.json").write_text(json.dumps(recs, ensure_ascii=False, indent=2))
    with (outdir / "chats.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["chat", "direction", "timestamp_utc", "body"])
        w.writeheader(); w.writerows(recs)
    return len(recs)


# ----------------------------- main ----------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline WhatsApp decrypt (no device modification).")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--from-dir"); src.add_argument("--from-tar")
    src.add_argument("--from-ab"); src.add_argument("--from-image")
    ap.add_argument("--fs-offset", type=int, default=0)
    ap.add_argument("--key-file"); ap.add_argument("--hex-key"); ap.add_argument("--backup")
    ap.add_argument("-o", "--outdir", default="wa_out")
    ap.add_argument("--dump-chats", action="store_true")
    args = ap.parse_args(argv)

    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    manifest = {"tool": "whatsapp_offline_extract", "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "read_only": True, "device_modified": False, "keys": [], "backups": [], "outputs": [], "custody": []}

    keys, backups = {}, {}
    if args.from_dir:
        keys, backups = _collect_from_dir(Path(args.from_dir))
    elif args.from_tar:
        keys, backups = _collect_from_tar(Path(args.from_tar))
    elif args.from_ab:
        keys, backups = _collect_from_ab(Path(args.from_ab))
    elif args.from_image:
        keys, backups = _collect_from_image(Path(args.from_image), args.fs_offset)
    if args.key_file:
        keys[args.key_file] = Path(args.key_file).read_bytes()
    if args.backup:
        backups[args.backup] = Path(args.backup).read_bytes()

    for src_name, kb in keys.items():
        manifest["keys"].append({"source": src_name, "size": len(kb), "sha256": _sha256(kb)})
        manifest["custody"].append(f"Read key {src_name} read-only ({len(kb)} B, sha256={_sha256(kb)[:16]}…)")
    key_file_bytes = next(iter(keys.values()), None)

    if not backups:
        print("No msgstore.*.cryptNN backups found in the source.", file=sys.stderr)
    decrypted = 0
    for src_name, blob in backups.items():
        fmt = detect_format(blob)
        rec = {"source": src_name, "format": fmt, "size": len(blob), "sha256": _sha256(blob)}
        try:
            plain = decrypt_backup(blob, hex_key=args.hex_key, key_file=key_file_bytes)
            out_db = outdir / (os.path.basename(src_name).split(".crypt")[0] + ".db")
            out_db.write_bytes(plain)
            rec["decrypted_to"] = out_db.name
            rec["decrypted_sha256"] = _sha256(plain)
            manifest["outputs"].append(out_db.name)
            manifest["custody"].append(f"Decrypted {os.path.basename(src_name)} -> {out_db.name} offline")
            decrypted += 1
            print(f"[ok] {src_name} ({fmt}) -> {out_db}")
            if args.dump_chats:
                n = dump_chats(out_db, outdir)
                rec["messages_dumped"] = n
                print(f"     dumped {n} messages -> chats.csv / chats.json")
        except WhatsAppKeyError as e:
            rec["error"] = str(e)
            print(f"[!!] {src_name}: {e}", file=sys.stderr)
        manifest["backups"].append(rec)

    (outdir / "extract_manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\nManifest: {outdir/'extract_manifest.json'}  (decrypted {decrypted}/{len(backups)})")
    return 0 if decrypted or not backups else 2


if __name__ == "__main__":
    raise SystemExit(main())
