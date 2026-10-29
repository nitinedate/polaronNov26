"""Decrypt agent — Android WhatsApp acquire + decrypt in one accountable step.

Runs during Android acquisition (invoked by the ADB adapter). It carries out the
Monolith Forensics Android WhatsApp process and hands the result to the project's
existing fail-closed decryptor so the pipeline gets a plaintext ``msgstore.db``.

Design decisions a reviewer should see:

* **Forensic default is read-only.** With no authorization the agent pulls the
  public WhatsApp tree and key file, discovers any existing ``.crypt1x`` backup,
  and decrypts it with key material already collected or entered in Intake. The
  evidence device is not modified. This is the whole PDF *minus* its device-
  writing steps, which most cases never need because a backup/key already exists.

* **The PDF's on-device steps (6-15) WRITE to the evidence device.** Generating a
  64-digit key and creating a new encrypted backup changes the handset. That is
  opt-in only: ``AUTH_GENERATE_KEY_AND_BACKUP`` must be present in the request's
  authorized actions, and the examiner must supply the 64-digit key WhatsApp
  shows (there is no reproducible public API to script those screens). Every
  device-modifying action, with before/after state, is written to the custody
  record so the report can disclose exactly what was done to the device.

* **No key is ever invented.** Decryption only uses keys the examiner collected
  or entered. The agent never brute-forces or derives a key from ciphertext.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from app.services.mobile_acquire.whatsapp_device_driver import (
    PUBLIC_WHATSAPP_BUSINESS_MEDIA,
    PUBLIC_WHATSAPP_MEDIA,
    DriverResult,
    WhatsAppDeviceDriver,
    normalize_64_digit_key,
)

# Authorized-action token the examiner must grant to allow on-device writes.
AUTH_GENERATE_KEY_AND_BACKUP = "whatsapp_generate_key_and_backup"
# A second, independent override the examiner must ALSO grant before any
# device-modifying step can run. Authorizing the backup action alone is not
# enough; this makes an accidental single-flag authorization fail closed.
AUTH_ALLOW_DEVICE_MODIFICATION = "allow_device_modification"

# Read-only decryption ladder, in order. Each rung uses data/keys that
# ALREADY exist; none generates a key or writes to the device.
LADDER = (
    "existing_backup_plus_supplied_64digit_key",   # crypt15 + examiner 64-digit key
    "existing_backup_plus_extracted_device_key",   # crypt12/14 + pulled files/key
    "live_private_db_via_existing_root",            # /data/data msgstore.db (root present)
    "already_plaintext_sqlite",                     # a plaintext msgstore.db on disk
)

# Manual, device-modifying steps (verbatim intent of PDF steps 6-15). The agent
# does not tap these; it records them for the examiner and the report.
ON_DEVICE_MANUAL_STEPS: tuple[str, ...] = (
    "In WhatsApp: Settings > Chats > Chat Backup.",
    "Open 'End-to-end encrypted backup'.",
    "Choose 'More options' > '64-digit encryption key'.",
    "Tap 'Generate your 64-digit key' and copy the key (long-press > Copy).",
    "Record the 64-digit key off-device; losing it permanently blocks the backup.",
    "Continue > 'I Saved My 64-digit Key' > 'Create' to make the encrypted backup.",
    "Return here, enter the 64-digit key, and confirm so the new backup is pulled and decrypted.",
)


@dataclass
class DecryptAgentRequest:
    adb: str = "adb"
    serial: str = ""
    out_dir: Path = field(default_factory=lambda: Path("."))
    # Authorized on-device actions (from AcquisitionRequest.authorized_actions).
    authorized_actions: tuple[str, ...] = ()
    # The 64-digit key the examiner read from WhatsApp (only when a new backup
    # was created on-device, or when the examiner already has the root key).
    supplied_64_digit_key: str = ""
    # Key material already captured in Intake / acquisition (hex strings / files).
    intake_key_candidates: tuple[str, ...] = ()
    include_business: bool = True
    # Try the read-only root rung (reads the live private DB only when root is
    # ALREADY present; never escalates). On by default; it can only read.
    try_live_private_db: bool = True
    cancel: Callable[[], bool] | None = None

    @property
    def device_modification_allowed(self) -> bool:
        """Both the action AND the independent override must be present."""
        return (
            AUTH_GENERATE_KEY_AND_BACKUP in self.authorized_actions
            and AUTH_ALLOW_DEVICE_MODIFICATION in self.authorized_actions
        )


@dataclass
class DecryptAgentResult:
    ok: bool = False
    stage: str = "decrypt_agent"
    device_modified: bool = False
    pulled_dirs: list[str] = field(default_factory=list)
    encrypted_backups: list[dict[str, Any]] = field(default_factory=list)
    decrypted_databases: list[dict[str, Any]] = field(default_factory=list)
    key_candidates_used: int = 0
    # Which read-only rung produced each database, and why rungs were skipped.
    ladder: list[dict[str, Any]] = field(default_factory=list)
    read_only: bool = True
    steps: list[dict[str, Any]] = field(default_factory=list)
    custody: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "stage": self.stage,
            "device_modified": self.device_modified,
            "pulled_dirs": self.pulled_dirs,
            "encrypted_backups": self.encrypted_backups,
            "decrypted_databases": self.decrypted_databases,
            "key_candidates_used": self.key_candidates_used,
            "ladder": self.ladder,
            "read_only": self.read_only,
            "steps": self.steps,
            "custody": self.custody,
            "limitations": self.limitations,
            "errors": self.errors,
        }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _custody(result: DecryptAgentResult, actor: str, detail: str, location: str = "") -> None:
    try:
        from app.services.mobile_acquire.audit import custody_entry

        result.custody.append(custody_entry("collection", actor=actor, detail=detail, location=location))
    except Exception:
        from datetime import datetime, timezone

        result.custody.append({
            "stage": "collection", "actor": actor, "detail": detail,
            "location": location, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        })


class WhatsAppDecryptAgent:
    """Orchestrates the device driver + the project's decrypt layer."""

    name = "whatsapp_decrypt_agent"

    def __init__(self, driver: WhatsAppDeviceDriver | None = None) -> None:
        self._driver = driver

    def _driver_for(self, req: DecryptAgentRequest) -> WhatsAppDeviceDriver:
        return self._driver or WhatsAppDeviceDriver(adb=req.adb, serial=req.serial)

    # -----------------------------------------------------------------
    def run(self, req: DecryptAgentRequest) -> DecryptAgentResult:
        result = DecryptAgentResult()
        driver = self._driver_for(req)
        req.out_dir.mkdir(parents=True, exist_ok=True)

        # PDF step 3: confirm the device is visible and authorized.
        confirm = driver.confirm_device()
        result.steps.append({"name": confirm.name, "ok": confirm.ok, "detail": confirm.detail})
        if not confirm.ok:
            result.errors.append(confirm.detail)
            result.limitations.append("WhatsApp decrypt agent did not run: device not acquirable over ADB.")
            return result

        if not driver.whatsapp_installed("com.whatsapp") and not (
            req.include_business and driver.whatsapp_installed("com.whatsapp.w4b")
        ):
            result.limitations.append("WhatsApp is not installed on this device; decrypt agent skipped.")
            result.ok = True
            return result

        # PDF steps 4-5: preserve a copy of the public WhatsApp tree (read-only).
        pulls: list[tuple[str, str]] = [(PUBLIC_WHATSAPP_MEDIA, "com.whatsapp")]
        if req.include_business:
            pulls.append((PUBLIC_WHATSAPP_BUSINESS_MEDIA, "com.whatsapp.w4b"))
        for remote, label in pulls:
            if req.cancel and req.cancel():
                result.limitations.append("Cancelled by examiner during WhatsApp public-tree pull.")
                return result
            dest = req.out_dir / "public" / label
            step = driver.pull_public_tree(remote, dest)
            result.steps.append({"name": step.name, "ok": step.ok, "detail": step.detail})
            if step.ok:
                result.pulled_dirs.append(str(dest))
                _custody(result, "decrypt_agent", f"Read-only pull of {remote}.", str(dest))
            else:
                result.limitations.append(f"{remote}: {step.detail}")

        # Rung 3 (read-only): read the live private DB when root is ALREADY
        # present. This never roots, unlocks or modifies the device.
        if req.try_live_private_db:
            if req.cancel and req.cancel():
                result.limitations.append("Cancelled by examiner before live private read.")
                return result
            live = driver.pull_live_private_db(req.out_dir / "live_private")
            result.steps.append({"name": live.name, "ok": live.ok, "detail": live.detail})
            if live.ok:
                _custody(result, "decrypt_agent",
                         f"Read-only capture of live WhatsApp private data ({live.detail}).",
                         str(req.out_dir / "live_private"))

        # Run the enforced read-only decryption ladder.
        self._run_ladder(req, result)

        # Device-modifying path (PDF steps 6-15) is the explicit LAST RESORT and
        # requires BOTH the backup action and the independent override. It runs
        # only when the ladder produced nothing.
        if not result.decrypted_databases and AUTH_GENERATE_KEY_AND_BACKUP in req.authorized_actions:
            if req.device_modification_allowed:
                self._generate_key_and_backup(driver, req, result)
                self._run_ladder(req, result)  # decrypt the freshly created backup
            else:
                result.limitations.append(
                    "Backup creation was requested but blocked: it modifies the evidence "
                    f"device and also requires the '{AUTH_ALLOW_DEVICE_MODIFICATION}' override. "
                    "Acquisition stayed read-only."
                )
        elif not result.decrypted_databases:
            result.limitations.append(
                "No read-only path yielded a WhatsApp database. Options that do NOT modify the "
                "device: supply the 64-digit key for an existing crypt15 backup; capture files/key "
                "or the live DB with an authorized root/full-file-system method. Creating a new "
                "backup on the device is a separate, authorized last resort."
            )

        result.ok = not result.errors
        return result

    # -----------------------------------------------------------------
    def _generate_key_and_backup(
        self, driver: WhatsAppDeviceDriver, req: DecryptAgentRequest, result: DecryptAgentResult
    ) -> None:
        """PDF steps 6-15 — writes to the evidence device. Authorized only."""
        before = driver.capture_backup_screen_state()
        _custody(result, "examiner",
                 "Authorized on-device action: generate 64-digit key and create encrypted backup. "
                 f"Pre-state backups={len(before.get('backups') or [])}.")
        result.device_modified = True
        result.read_only = False

        opened = driver.open_backup_settings()
        result.steps.append({"name": opened.name, "ok": opened.ok, "detail": opened.detail})
        # The manual steps are recorded; the agent cannot reproducibly tap them.
        result.steps.append({
            "name": "on_device_manual_steps", "ok": True,
            "detail": "Examiner must perform the WhatsApp backup steps on the device.",
            "manual_steps": list(ON_DEVICE_MANUAL_STEPS),
        })

        key = normalize_64_digit_key(req.supplied_64_digit_key)
        if not key:
            result.limitations.append(
                "Authorized to create a backup, but no valid 64-digit key was supplied. "
                "Perform the on-device steps, then re-run with the 64-digit key."
            )
            return

        # The supplied key is a decryption candidate for the new crypt15 backup.
        req.intake_key_candidates = (*req.intake_key_candidates, key)
        after = driver.capture_backup_screen_state()
        new_backups = [b for b in after.get("backups", []) if b not in before.get("backups", [])]
        _custody(result, "device",
                 f"Post-state backups={len(after.get('backups') or [])}; "
                 f"new={len(new_backups)}; dir_mtime {before.get('databases_dir_mtime')} -> "
                 f"{after.get('databases_dir_mtime')}.")

        # Re-pull the public tree so the new crypt15 backup is captured (PDF 16).
        dest = req.out_dir / "public_after_backup" / "com.whatsapp"
        step = driver.pull_public_tree(PUBLIC_WHATSAPP_MEDIA, dest)
        result.steps.append({"name": "repull_after_backup", "ok": step.ok, "detail": step.detail})
        if step.ok:
            result.pulled_dirs.append(str(dest))

    # -----------------------------------------------------------------
    def _find_encrypted_backups(self, req: DecryptAgentRequest) -> list[Path]:
        found: list[Path] = []
        for base in req.out_dir.rglob("msgstore*.crypt*"):
            if base.is_file():
                found.append(base)
        # Deterministic order; newest crypt version last so it wins ties.
        return sorted(set(found), key=lambda p: (p.name, len(p.name)))

    def _candidate_objects(self, req: DecryptAgentRequest) -> list[Any]:
        from app.services.mobile_forensic.whatsapp_crypt import WhatsAppKeyCandidate

        candidates: list[Any] = []
        seen: set[str] = set()
        # Explicit intake/supplied hex keys.
        for material in req.intake_key_candidates:
            m = (material or "").strip()
            if m and m not in seen:
                seen.add(m)
                candidates.append(WhatsAppKeyCandidate(material=m, source="case_intake"))
        # Any 158-byte files/key or encrypted_backup.key pulled from the device.
        for key_file in [*req.out_dir.rglob("key"), *req.out_dir.rglob("encrypted_backup.key")]:
            try:
                if key_file.is_file() and key_file.stat().st_size <= 512:
                    blob = key_file.read_bytes()
                    digest = hashlib.sha256(blob).hexdigest()
                    if digest not in seen:
                        seen.add(digest)
                        candidates.append(WhatsAppKeyCandidate(material=blob, source=f"device:{key_file.name}"))
            except OSError:
                continue
        return candidates

    def _classify_rung(self, backup, candidates) -> str:
        """Best-effort label for which read-only rung a backup belongs to."""
        from app.services.mobile_forensic.whatsapp_crypt import classify_container

        try:
            head = backup.read_bytes()[:128]
        except OSError:
            head = b""
        container = classify_container(head, backup.name)
        if container == "sqlite":
            return "already_plaintext_sqlite"
        if container == "crypt15":
            return "existing_backup_plus_supplied_64digit_key"
        if container in ("crypt12", "crypt14"):
            return "existing_backup_plus_extracted_device_key"
        return "existing_backup_plus_supplied_64digit_key"

    def _run_ladder(self, req: DecryptAgentRequest, result: DecryptAgentResult) -> None:
        """Enforced read-only ladder: decrypt existing backups and live DBs only.

        Every key used already exists (examiner-supplied 64-digit key, extracted
        files/key, or a plaintext/live DB). No key is generated; the device is
        not written to by any step here.
        """
        from app.services.mobile_forensic.whatsapp_crypt import (
            decrypt_with_candidates,
            last_decrypt_diagnostics,
            looks_like_sqlite,
        )

        candidates = self._candidate_objects(req)
        result.key_candidates_used = len(candidates)
        decrypted_dir = req.out_dir / "decrypted"
        already = {d["from_backup"] for d in result.decrypted_databases}

        # msgstore*.crypt* (pulled backups) and any live/plaintext msgstore.db.
        sources: list[Path] = [b for b in self._find_encrypted_backups(req) if b.name not in already]
        for live in req.out_dir.rglob("*msgstore.db"):
            if live.is_file() and live.name not in already:
                sources.append(live)

        for src in sources:
            if req.cancel and req.cancel():
                result.limitations.append("Cancelled by examiner during decryption.")
                return
            try:
                data = src.read_bytes()
            except OSError as exc:
                result.limitations.append(f"{src.name}: unreadable ({exc}).")
                continue
            rung = "already_plaintext_sqlite" if looks_like_sqlite(data) else self._classify_rung(src, candidates)
            entry: dict[str, Any] = {
                "source": str(src), "name": src.name, "rung": rung,
                "source_sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
            }

            if looks_like_sqlite(data):
                # Rung 4 / rung 3 output: already plaintext, just register it.
                decrypted_dir.mkdir(parents=True, exist_ok=True)
                out_db = decrypted_dir / (src.name if src.name.endswith(".db") else src.name + ".db")
                out_db.write_bytes(data)
                plain = data
            else:
                plain = decrypt_with_candidates(data, candidates, path=src.name)

            if plain is None:
                diag = last_decrypt_diagnostics()
                entry.update({"decrypted": False, "reason": diag.get("reason"), "container": diag.get("container")})
                result.encrypted_backups.append(entry)
                result.ladder.append({"rung": rung, "source": src.name, "result": "blocked",
                                      "reason": diag.get("reason")})
                continue

            if not looks_like_sqlite(data):
                decrypted_dir.mkdir(parents=True, exist_ok=True)
                out_db = decrypted_dir / (src.stem if src.suffix.startswith(".crypt") else src.name)
                if not out_db.name.endswith(".db"):
                    out_db = out_db.with_suffix(".db")
                out_db.write_bytes(plain)
            diag = last_decrypt_diagnostics()
            entry.update({
                "decrypted": True, "decrypted_path": str(out_db),
                "decrypted_sha256": _sha256(out_db), "decrypted_size_bytes": out_db.stat().st_size,
                "container": diag.get("container") or ("sqlite" if looks_like_sqlite(data) else None),
                "key_source": diag.get("key_source") or ("none (plaintext)" if looks_like_sqlite(data) else None),
            })
            result.encrypted_backups.append(entry)
            result.decrypted_databases.append({
                "database": str(out_db), "from_backup": src.name,
                "sha256": entry["decrypted_sha256"], "rung": rung,
            })
            result.ladder.append({"rung": rung, "source": src.name, "result": "decrypted",
                                  "key_source": entry.get("key_source")})
            _custody(result, "decrypt_agent",
                     f"Decrypted {src.name} -> {out_db.name} via '{rung}' "
                     f"(container={entry.get('container')}, key={entry.get('key_source')}).",
                     str(out_db))

    # -----------------------------------------------------------------
    def write_manifest(self, req: DecryptAgentRequest, result: DecryptAgentResult) -> Path:
        """Per-run manifest. Never contains raw key bytes."""
        manifest = req.out_dir / "whatsapp_decrypt_agent_manifest.json"
        manifest.write_text(json.dumps(result.as_dict(), indent=2, default=str), encoding="utf-8")
        return manifest
