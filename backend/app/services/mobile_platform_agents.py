"""iOS Agent and Android Agent — exclusive owners of phone extract + RAG.

Each agent auto-detects its platform from the adapter, OS family, job seed,
or evidence path. An iOS job never runs Android extract/parse/inventory/RAG,
and the reverse is also refused.
"""

from __future__ import annotations

from typing import Any, Literal

from app.services.mobile_os import normalize_mobile_os

MobilePlatform = Literal["ios", "android"]

IOSAGENT_ID = "iosagent"
ANDROIDAGENT_ID = "androidagent"
PLATFORM_AGENT_IDS = frozenset({IOSAGENT_ID, ANDROIDAGENT_ID})

IOSAGENT_LABEL = "iOS Agent"
ANDROIDAGENT_LABEL = "Android Agent"

OWNED_STAGES = (
    "extract",
    "materialize",
    "ocr",
    "parse",
    "rag_index",
    "rag_enrich",
    "graph_sync",
    "artifact_inventory",
)

_IOS_ADAPTERS = frozenset({"ios_lockdown", "ios", "ios_backup"})
_ANDROID_ADAPTERS = frozenset({"android_adb", "android_mtp", "android", "android_backup"})

_IOS_NAME_HINTS = (
    "iphone",
    "ipad",
    "ipod",
    "ios",
    "apple",
    "manifest.db",
    "manifest.plist",
    "ios_backup",
    "chatstorage.sqlite",
    "sms.db",
    "addressbook.sqlitedb",
    "vid_05ac",
)
_ANDROID_NAME_HINTS = (
    "android",
    "samsung",
    "galaxy",
    "pixel",
    "xiaomi",
    "huawei",
    "honor",
    "oneplus",
    "oppo",
    "vivo",
    "mtp_shared",
    "adb_logical",
    "com.whatsapp",
    "com.android",
    "/data/data/",
    "data/data/",
)


class PlatformMismatchError(ValueError):
    """Raised when an agent is asked to work a phone it does not own."""


def owner_agent_id(platform: str | None) -> str | None:
    family = normalize_mobile_os(platform)
    if family == "ios":
        return IOSAGENT_ID
    if family == "android":
        return ANDROIDAGENT_ID
    return None


def owner_agent_label(platform: str | None) -> str | None:
    aid = owner_agent_id(platform)
    if aid == IOSAGENT_ID:
        return IOSAGENT_LABEL
    if aid == ANDROIDAGENT_ID:
        return ANDROIDAGENT_LABEL
    return None


def platform_for_agent(agent_id: str | None) -> MobilePlatform | None:
    aid = (agent_id or "").strip().lower().replace("_", "")
    if aid in {"iosagent", "iososagent"}:
        return "ios"
    if aid in {"androidagent", "androidosagent"}:
        return "android"
    return None


def detect_mobile_platform(*hints: Any) -> MobilePlatform | None:
    """Classify a device / job / path as ios or android. None if unknown."""
    seen_ios = False
    seen_android = False
    for hint in hints:
        family = _classify_one(hint)
        if family == "ios":
            seen_ios = True
        elif family == "android":
            seen_android = True
    if seen_ios and seen_android:
        return None
    if seen_ios:
        return "ios"
    if seen_android:
        return "android"
    return None


def _classify_one(hint: Any) -> MobilePlatform | None:
    if hint is None:
        return None
    if isinstance(hint, dict):
        for key in (
            "owner_agent",
            "adapter",
            "os_family",
            "mobile_os",
            "axiom_platform",
            "evidence_platform",
            "platform",
            "os_hint",
            "device_label",
            "model",
            "name",
            "type",
            "source_type",
        ):
            family = _classify_one(hint.get(key))
            if family:
                return family
        detected = hint.get("detected_os")
        if isinstance(detected, dict):
            family = _classify_one(detected.get("family") or detected.get("os_family"))
            if family:
                return family
        for key in ("device_id", "udid", "serial", "path", "host_path", "evidence_folder", "working"):
            family = _classify_text(str(hint.get(key) or ""))
            if family:
                return family
        return None
    if isinstance(hint, (list, tuple)):
        for item in hint:
            family = _classify_one(item)
            if family:
                return family
        return None
    return _classify_text(str(hint))


def _classify_text(raw: str) -> MobilePlatform | None:
    text = (raw or "").strip().lower().replace("\\", "/")
    if not text:
        return None
    compact = text.replace("_", "").replace("-", "")
    if compact in {"iosagent", "iososagent"}:
        return "ios"
    if compact in {"androidagent", "androidosagent"}:
        return "android"
    adapter = text.split("/")[-1]
    if adapter in _IOS_ADAPTERS or text in _IOS_ADAPTERS:
        return "ios"
    if adapter in _ANDROID_ADAPTERS or text in _ANDROID_ADAPTERS:
        return "android"
    norm = normalize_mobile_os(text)
    if norm in {"ios", "android"}:
        return norm  # type: ignore[return-value]
    if any(token in text for token in _IOS_NAME_HINTS):
        return "ios"
    if any(token in text for token in _ANDROID_NAME_HINTS):
        return "android"
    return None


def explicit_evidence_platform(disk_source: dict[str, Any] | None) -> MobilePlatform | None:
    """Platform stamped on the evidence record.

    ``mobile_os`` of ``other`` is not a platform. A conflicting job type must
    not erase this: the supervisor uses it to decide which product may run.
    """
    ds = disk_source if isinstance(disk_source, dict) else {}
    mobile_os = normalize_mobile_os(str(ds.get("mobile_os") or ""))
    if mobile_os not in {"ios", "android"}:
        mobile_os = None
    return detect_mobile_platform(
        ds.get("owner_agent"),
        mobile_os,
        ds.get("axiom_platform"),
        ds.get("evidence_platform"),
        ds.get("os_family"),
    )


def mobile_os_family_from_job_row(row: dict[str, Any] | None) -> MobilePlatform | None:
    from app.forensic_common.job_types import _as_dict

    if not row:
        return None
    ds = _as_dict(row.get("disk_source"))
    # A job opened on Disk Forensics stays there. A desktop image stays there
    # even when phone files copied onto that disk make a detector say Android or iOS.
    if str(row.get("type") or "") in {"host_disk", "forensic", "disk"} or is_physical_disk_image(ds):
        return None
    # Evidence owner wins over jobs.type. An android_mobile row whose package
    # was identified as iOS must be supervised by iOS, or Android will resume
    # a task that dies before it can heartbeat.
    explicit = explicit_evidence_platform(ds)
    if explicit:
        return explicit
    family = detect_mobile_platform(
        ds.get("owner_agent"),
        ds.get("mobile_os"),
        ds.get("axiom_platform"),
        ds.get("evidence_platform"),
        ds.get("adapter"),
        ds.get("os_family"),
        ds,
        row.get("type"),
    )
    if family:
        return family
    jtype = str(row.get("type") or "")
    if jtype in {"ios_backup", "ios_mobile"}:
        return "ios"
    if jtype in {"android_backup", "android_mobile"}:
        return "android"
    return None



def detect_mobile_platform_from_evidence_paths(paths: list[str]) -> MobilePlatform | None:
    """Classify materialized mobile evidence using strong Android/iOS artefact markers.

    This is intentionally evidence-first and conservative. Generic words such as
    ``mobile`` or ``backup`` do not decide ownership. A platform is returned only
    when one side has a clear score advantage, otherwise the result is unknown so
    an examiner-selected platform is not silently replaced by weak filename hints.
    """
    ios_score = 0
    android_score = 0
    for raw in paths or []:
        text = str(raw or "").replace('\\', '/').lower()
        if not text:
            continue
        # Strong iOS artefacts / backup layout.
        if 'chatstorage.sqlite' in text: ios_score += 5
        if 'manifest.db' in text or 'manifest.plist' in text: ios_score += 5
        if 'mobilebackup' in text or '/private/var/mobile/' in text: ios_score += 4
        if 'addressbook.sqlitedb' in text or '/library/sms/sms.db' in text: ios_score += 4
        if '/var/mobile/' in text or 'com.apple.' in text: ios_score += 2
        # Strong Android artefacts / filesystem layout.
        if 'msgstore.db' in text or '.crypt12' in text or '.crypt14' in text or '.crypt15' in text: android_score += 5
        if '/data/data/' in text or '/data/user/0/' in text: android_score += 5
        if 'packages.xml' in text or 'build.prop' in text: android_score += 4
        if 'com.android.' in text or 'com.google.android.' in text: android_score += 2
        if '/sdcard/' in text or '/storage/emulated/' in text: android_score += 2
    if ios_score >= 5 and ios_score >= android_score + 3:
        return 'ios'
    if android_score >= 5 and android_score >= ios_score + 3:
        return 'android'
    return None


_DISK_IMAGE_FORMATS = frozenset({"e01", "ewf", "ex01", "s01", "raw", "dd", "aff", "vmdk", "vhd", "vhdx"})
_DISK_IMAGE_MODES = frozenset({"ewf", "raw"})


def is_physical_disk_image(disk_source: dict | None) -> bool:
    """True for a desktop/server image. Phone backups are not disk images.

    A Windows PC image often contains copies of Android files. Those copies must
    not move the job onto the Android product.
    """
    ds = disk_source if isinstance(disk_source, dict) else {}
    source = str(ds.get("source_type") or "").strip().lower()
    if source in {"mobile", "android_backup", "ios_backup"}:
        return False
    image_format = str(ds.get("format") or "").strip().lower()
    mode = str(ds.get("mode") or "").strip().lower()
    return source == "disk" and (image_format in _DISK_IMAGE_FORMATS or mode in _DISK_IMAGE_MODES)


def _release_disk_image_from_mobile(db, job_id: str, row: dict, ds: dict) -> None:
    """Put a desktop image back on Disk Forensics after a phone detector claimed it."""
    from app.db.sql_helpers import execute
    from app.forensic_common.job_types import MOBILE_JOB_TYPES

    jtype = str(row.get("type") or "")
    platform = str(ds.get("evidence_platform") or ds.get("axiom_platform") or "").strip().lower()
    if (
        jtype not in MOBILE_JOB_TYPES
        and platform not in {"android", "ios"}
        and not ds.get("mobile_os")
        and not ds.get("owner_agent")
    ):
        return
    cleaned = dict(ds)
    for key in (
        "mobile_os",
        "owner_agent",
        "owner_agent_label",
        "os_selection_source",
        "os_mismatch_warning",
    ):
        cleaned.pop(key, None)
    cleaned["source_type"] = "disk"
    cleaned["evidence_platform"] = "Windows"
    cleaned["axiom_platform"] = "Windows"
    detected = cleaned.get("detected_os")
    if isinstance(detected, dict) and str(detected.get("family") or "").strip().lower() == "android":
        detected = dict(detected)
        detected["family"] = "windows"
        cleaned["detected_os"] = detected
    import json

    execute(
        db,
        "UPDATE jobs SET type='host_disk', disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:jid",
        {"ds": json.dumps(cleaned), "jid": job_id},
    )
    try:
        from app.services.disk_build_log import write_disk_log

        write_disk_log(
            db,
            job_id,
            "Desktop disk image stays on Disk Forensics. Phone-file copies inside the image do not move the job to Android or iOS.",
            stage="evidence_register",
            level="warning",
        )
    except Exception:
        pass
    try:
        db.commit()
    except Exception:
        pass


def reconcile_mobile_platform_from_registered_evidence(db, job_id: str) -> MobilePlatform | None:
    """Verify Android/iPhone ownership from registered evidence before agents run.

    The function only changes ownership when the evidence markers are strong. It
    records a mismatch warning, corrects the canonical job type, and stamps the
    evidence/AXIOM platform so the wrong mobile agent cannot continue processing.
    A physical disk image is never reclassified: Android files on a PC are evidence,
    not a phone acquisition.
    """
    from app.db.sql_helpers import execute, fetchall, fetchone
    from app.forensic_common.job_types import _as_dict

    row = fetchone(db, 'SELECT type, disk_source FROM jobs WHERE id=:jid', {'jid': job_id})
    if not row:
        return None
    disk_source = _as_dict(row.get("disk_source"))
    if str(row.get("type") or "") in {"host_disk", "forensic", "disk"} or is_physical_disk_image(disk_source):
        _release_disk_image_from_mobile(db, job_id, row, disk_source)
        return None
    samples = fetchall(
        db,
        """SELECT file_path FROM job_artifacts
           WHERE job_id=:jid AND (
             lower(file_path) LIKE '%chatstorage.sqlite%' OR
             lower(file_path) LIKE '%manifest.db%' OR
             lower(file_path) LIKE '%manifest.plist%' OR
             lower(file_path) LIKE '%addressbook.sqlitedb%' OR
             lower(file_path) LIKE '%/private/var/mobile/%' OR
             lower(file_path) LIKE '%/var/mobile/%' OR
             lower(file_path) LIKE '%msgstore.db%' OR
             lower(file_path) LIKE '%.crypt12%' OR lower(file_path) LIKE '%.crypt14%' OR lower(file_path) LIKE '%.crypt15%' OR
             lower(file_path) LIKE '%/data/data/%' OR lower(file_path) LIKE '%/data/user/0/%' OR
             lower(file_path) LIKE '%packages.xml%' OR lower(file_path) LIKE '%build.prop%' OR
             lower(file_path) LIKE '%/storage/emulated/%'
           ) ORDER BY file_path LIMIT 500""",
        {'jid': job_id},
    )
    evidence_files = fetchall(
        db,
        """SELECT original_name, host_path, relative_path FROM evidence_files
           WHERE job_id=:jid ORDER BY created_at LIMIT 500""",
        {'jid': job_id},
    )
    path_hints = [str(r.get('file_path') or '') for r in samples]
    for r in evidence_files or []:
        path_hints.extend([
            str(r.get('original_name') or ''),
            str(r.get('host_path') or ''),
            str(r.get('relative_path') or ''),
        ])
    detected = detect_mobile_platform_from_evidence_paths(path_hints)
    if not detected:
        detected = detect_mobile_platform(*path_hints)
    if not detected:
        return mobile_os_family_from_job_row(row)

    ds = _as_dict(row.get('disk_source'))
    prior = mobile_os_family_from_job_row(row)
    if prior and prior != detected:
        ds['os_mismatch_warning'] = (
            f"Registered evidence identifies {detected}; previous mobile selection was {prior}. "
            f"Ownership automatically reassigned to {'iOS Agent' if detected == 'ios' else 'Android Agent'}."
        )
    ds = persist_owner_on_disk_source(ds, detected)
    # Evidence classification is authoritative for agent ownership.
    ds['mobile_os'] = detected
    ds['os_selection_source'] = 'evidence_verified'
    ds['evidence_platform'] = 'iOS' if detected == 'ios' else 'Android'
    ds['axiom_platform'] = ds['evidence_platform']
    canonical = 'ios_mobile' if detected == 'ios' else 'android_mobile'
    import json
    execute(
        db,
        'UPDATE jobs SET type=:typ, disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:jid',
        {'typ': canonical, 'ds': json.dumps(ds), 'jid': job_id},
    )
    try:
        from app.services.disk_build_log import write_disk_log
        write_disk_log(
            db, job_id,
            f"Mobile platform verified from evidence: {detected}. Owner={'iOS Agent' if detected == 'ios' else 'Android Agent'}.",
            stage='mobile_platform_detection',
            level='warning' if prior and prior != detected else 'info',
        )
    except Exception:
        pass
    try:
        db.commit()
    except Exception:
        pass
    return detected

def owner_agent_for_job(db, job_id: str) -> str | None:
    from app.db.sql_helpers import fetchone

    row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
    return owner_agent_id(mobile_os_family_from_job_row(row))


def current_service_owns_job(db, job_id: str) -> bool:
    """True when this process is the product that should run the job.

    Disk, Android, and iOS share one firm database, so each product's supervisor
    can see the others' jobs. Only the owning product may dispatch work.
    """
    from app.db.sql_helpers import fetchone
    from app.service_identity import (
        FORENSIC,
        MOBILE_ANDROID,
        MOBILE_EXTRACT,
        MOBILE_IOS,
        current_service,
    )

    row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
    family = mobile_os_family_from_job_row(row)
    svc = current_service()
    if svc == MOBILE_ANDROID:
        return family == "android"
    if svc == MOBILE_IOS:
        return family == "ios"
    if svc == MOBILE_EXTRACT:
        return family in {"android", "ios"}
    if svc == FORENSIC:
        return family is None
    return family is None


def assert_agent_owns_job(db, job_id: str, agent_id: str) -> str:
    """Return the owner id, or raise if this agent is the wrong platform."""
    wanted = platform_for_agent(agent_id)
    if not wanted:
        owner = owner_agent_for_job(db, job_id)
        return owner or agent_id
    from app.db.sql_helpers import fetchone

    row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
    family = mobile_os_family_from_job_row(row)
    if family and family != wanted:
        raise PlatformMismatchError(
            f"{owner_agent_label(wanted)} cannot process a {family} phone — "
            f"{owner_agent_label(family)} owns this job"
        )
    return owner_agent_id(wanted) or agent_id


def persist_owner_on_disk_source(disk_source: dict[str, Any] | None, platform: str | None) -> dict[str, Any]:
    out = dict(disk_source or {})
    family = normalize_mobile_os(platform) or detect_mobile_platform(out)
    if family not in {"ios", "android"}:
        return out
    out["mobile_os"] = family
    out["owner_agent"] = owner_agent_id(family)
    out["owner_agent_label"] = owner_agent_label(family)
    # When a platform has been verified, overwrite stale platform labels.
    # Keeping an old Android axiom/evidence label after detecting iOS creates
    # self-conflicting metadata and routes the next task back to Android.
    if family == "ios":
        out["axiom_platform"] = "iOS"
        out["evidence_platform"] = "iOS"
    else:
        out["axiom_platform"] = "Android"
        out["evidence_platform"] = "Android"
    return out


def owner_progress_from_stage_states(states: dict[str, dict[str, Any]]) -> tuple[str, int, str]:
    """Composite extract→RAG progress for the owning platform agent."""
    owned = (
        "extraction_agent",
        "materialize_agent",
        "ocr_agent",
        "parse_agent",
        "chunk_agent",
        "embed_agent",
        "entity_agent",
        "neo4j_agent",
        "annotation_agent",
        "ontology_agent",
        "artifacts_agent",
    )
    running: list[tuple[str, int, str]] = []
    pending = 0
    done = 0
    failed_detail = ""
    for aid in owned:
        entry = states.get(aid) if isinstance(states.get(aid), dict) else {}
        state = str(entry.get("state") or "pending")
        pct = int(entry.get("pct") or 0)
        label = str(entry.get("label") or aid)
        detail = str(entry.get("detail") or "")
        if state == "failed":
            failed_detail = detail or f"{label} failed"
        elif state == "running":
            running.append((label, pct, detail))
        elif state == "done":
            done += 1
        else:
            pending += 1
    if failed_detail:
        return "failed", min(99, max(1, int(100 * done / max(len(owned), 1)))), failed_detail
    if running:
        label, pct, detail = running[0]
        return "running", min(99, max(1, pct or 1)), detail or f"{label} in progress"
    if pending == 0 and done > 0:
        return "done", 100, "Phone extract and RAG complete"
    if done == 0 and pending == len(owned):
        return "pending", 0, "Waiting to start phone extract"
    overall = int(100 * done / max(len(owned), 1))
    return "running", min(99, max(1, overall)), f"{done}/{len(owned)} owned stages complete"
