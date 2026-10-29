"""V1.24: leave non-evidence ("noise") out of extraction.

* Game libraries are excluded automatically in Standard (never in Deep).
* Examiner review: pause after the file system is listed, leave folders out.
* Known-good (NSRL) files are dropped from the extraction index after hashing.
Nothing on the evidence is deleted; every exclusion is recorded.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

JOB = "11111111-2222-3333-4444-555555555555"


# ---------------------------------------------------------------------------
# Game libraries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,rule", [
    ("Program Files (x86)/Steam/steamapps/common/Cyberpunk/archive/pc/content/base.archive", "game_library:steam"),
    ("E:/SteamLibrary/steamapps/common/Elden Ring/Game/data0.bdt", "game_library:steam"),
    ("Program Files (x86)/Steam/steamapps/shadercache/1091500/fozpipelinesv6/x.foz", "game_library:steam"),
    ("Program Files/Epic Games/Fortnite/FortniteGame/Content/Paks/pakchunk0.pak", "game_library:epic"),
    ("XboxGames/Halo Infinite/Content/data.bin", "game_library:xbox"),
    ("Program Files/Riot Games/VALORANT/live/ShooterGame/Content/Paks/x.pak", "game_library:riot"),
    # kept: user content hidden in a game folder, launcher accounts/logs, saves
    ("Program Files (x86)/Steam/steamapps/common/Game/secret plans.docx", None),
    ("Program Files (x86)/Steam/steamapps/common/Game/wallet.kdbx", None),
    ("Program Files (x86)/Steam/userdata/123/config/localconfig.vdf", None),
    ("Program Files (x86)/Steam/config/loginusers.vdf", None),
    ("Users/alice/Documents/My Games/Skyrim/Saves/save1.ess", None),
    ("ProgramData/Epic/EpicGamesLauncher/Data/Logs/launcher.log", None),
])
def test_game_library_content_is_left_out_but_user_content_is_kept(path, rule):
    from app.services.extract_os_vendor_noise import classify_os_vendor_standard

    assert classify_os_vendor_standard(path, size_bytes=1 << 20, os_family="windows") == rule


def test_game_libraries_are_kept_in_deep_examination(monkeypatch):
    from app.services.extract_os_vendor_noise import should_skip_os_vendor

    monkeypatch.delenv("EXTRACT_OS_VENDOR_TREES", raising=False)  # Deep: vendor trees kept
    assert should_skip_os_vendor("Program Files/Epic Games/Fortnite/x.pak", size_bytes=1 << 20) == (False, None)


# ---------------------------------------------------------------------------
# Examiner review
# ---------------------------------------------------------------------------

def _nodes():
    GB = 1 << 30
    return [
        {"path": "Windows/System32/config/SYSTEM", "size_bytes": 20 << 20},
        {"path": "Windows/System32/drivers/x.sys", "size_bytes": 1 << 20},
        {"path": "VMs/Win7/Win7.vmdk", "size_bytes": 40 * GB},
        {"path": "VMs/Win7/Win7.vmx", "size_bytes": 4096},
        {"path": "Users/alice/Documents/plan.docx", "size_bytes": 50 << 10},
        {"path": "Users/alice/Downloads/backup.iso", "size_bytes": 3 * GB},
    ]


def test_summary_shows_where_the_bytes_are():
    from app.services.extract_review import summarize

    nodes = _nodes()
    all_nodes = nodes + [{"path": "Windows/WinSxS/a.dll", "size_bytes": 5 << 30}]
    s = summarize(nodes, all_nodes=all_nodes, filter_stats={"filtered_out": 1, "os_vendor_tree": 1, "enumerated": 7})
    folders = {f["path"]: f for f in s["folders"]}
    assert folders["VMs"]["bytes"] == 40 * (1 << 30) + 4096 and folders["VMs"]["files"] == 2
    assert {"Windows", "Users", "Users/alice"} <= set(folders)
    assert [b["path"] for b in s["big_files"]] == ["VMs/Win7/Win7.vmdk", "Users/alice/Downloads/backup.iso"]
    assert s["auto_excluded"] == {"files": 1, "bytes": 5 << 30, "rules": {"os_vendor_tree": 1}}
    assert s["total_files"] == 6


def test_exclusions_keep_named_artifacts_inside_excluded_folders(monkeypatch):
    from app.services import extract_review

    monkeypatch.setattr(extract_review, "_named_artifact", lambda p, fam: p.endswith("config/system"))
    kept, stats = extract_review.apply(_nodes(), ["Windows", "VMs", "users/alice/downloads/backup.iso"])
    assert [n["path"] for n in kept] == ["Windows/System32/config/SYSTEM", "Users/alice/Documents/plan.docx"]
    assert stats["examiner_excluded_files"] == 4 and stats["examiner_protected_artifacts"] == 1
    # Excluding the named artifact itself is honoured: the examiner chose that exact file.
    kept, _ = extract_review.apply(_nodes(), ["Windows/System32/config/SYSTEM"])
    assert "Windows/System32/config/SYSTEM" not in [n["path"] for n in kept]


@pytest.mark.parametrize("path,protected", [
    ("Windows/System32/config/SYSTEM", True),
    ("Windows/System32/winevt/Logs/Security.evtx", True),          # only a broad claim in the scope pack
    ("Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx", True),
    ("Windows/System32/Tasks/Microsoft/Windows/Updater", True),
    ("Windows/INF/setupapi.dev.log", True),
    ("Windows/System32/sru/SRUDB.dat", True),
    ("Windows/appcompat/Programs/Amcache.hve", True),
    ("Users/alice/NTUSER.DAT", True),
    ("Users/alice/AppData/Local/Google/Chrome/User Data/Default/History", True),
    ("Windows/System32/drivers/x.sys", False),
    ("VMs/Win7/Win7.vmdk", False),
    ("Users/alice/Videos/clip.mp4", False),
])
def test_named_artifacts_survive_an_examiner_exclusion(path, protected):
    from app.services import extract_review

    kept, stats = extract_review.apply([{"path": path, "size_bytes": 1}], ["Windows", "Users", "VMs"], os_family="windows")
    assert (len(kept) == 1) is protected


def test_clean_exclusions_rejects_traversal_and_duplicates():
    from app.services.extract_review import clean_exclusions

    assert clean_exclusions(["VMs/", "\\VMs", "../etc", "a/./b", "", "Users/x"]) == ["VMs", "Users/x"]
    with pytest.raises(ValueError):
        clean_exclusions([f"d{i}" for i in range(1001)])


@pytest.fixture
def review_env(monkeypatch):
    from app.services import extract_review

    store = {"ds": {}, "cp": None, "paused": None, "logs": []}
    monkeypatch.setattr(extract_review, "_load_ds", lambda db, job_id: json.loads(json.dumps(store["ds"])))
    monkeypatch.setattr(extract_review, "_save_ds", lambda db, job_id, ds: store.__setitem__("ds", ds))
    monkeypatch.setattr("app.services.disk_build_log.write_disk_log", lambda db, job_id, msg, **k: store["logs"].append(msg))
    monkeypatch.setattr("app.services.job_control.load_extraction_checkpoint", lambda db, job_id: store["cp"])
    monkeypatch.setattr("app.services.job_control.save_extraction_checkpoint", lambda db, job_id, cp: store.__setitem__("cp", cp))
    monkeypatch.setattr("app.services.job_control.mark_job_paused", lambda db, job_id, message=None: store.__setitem__("paused", message))
    monkeypatch.setattr(extract_review, "_named_artifact", lambda p, fam: p.endswith("config/system"))
    db = type("DB", (), {"commit": lambda self: None})()
    return store, db


def test_gate_does_nothing_unless_review_was_requested(review_env):
    from app.services.extract_review import gate

    store, db = review_env
    nodes = _nodes()
    assert gate(db, JOB, nodes=nodes, all_nodes=nodes, filter_stats={}, os_family="windows") == ("continue", nodes)
    assert store["paused"] is None


def test_gate_pauses_with_a_summary_and_keeps_the_plan(review_env):
    from app.services.extract_review import PAUSE_MESSAGE, gate
    from app.services.pipeline_supervisor import _is_auto_resumable_pause

    store, db = review_env
    store["ds"] = {"extract_review": {"required": True}, "intake": "client_remote"}
    decision, _ = gate(db, JOB, nodes=_nodes(), all_nodes=_nodes(), filter_stats={"filtered_out": 0},
                       os_family="windows", nodes_uri="s3://plan/nodes.zst", extract_mode="standard")
    assert decision == "pause" and store["paused"] == PAUSE_MESSAGE
    assert store["ds"]["extract_review"]["status"] == "pending"
    assert store["ds"]["extract_review"]["summary"]["total_files"] == 6
    assert store["cp"]["nodes_uri"] == "s3://plan/nodes.zst" and store["cp"]["extract_mode"] == "standard"
    # The supervisor must wait for the examiner, not resume this pause by itself.
    assert _is_auto_resumable_pause({"status": "paused", "error": PAUSE_MESSAGE}) is False


def test_gate_applies_an_approved_review(review_env):
    from app.services.extract_review import gate

    store, db = review_env
    store["ds"] = {"extract_review": {"required": True, "status": "approved", "excluded": ["Windows", "VMs"]}}
    stats = {"filtered_out": 10}
    decision, kept = gate(db, JOB, nodes=_nodes(), all_nodes=None, filter_stats=stats, os_family="windows")
    assert decision == "continue"
    assert [n["path"] for n in kept] == ["Windows/System32/config/SYSTEM", "Users/alice/Documents/plan.docx",
                                         "Users/alice/Downloads/backup.iso"]
    assert stats["examiner_excluded_files"] == 3 and stats["filtered_out"] == 13
    assert stats["examiner_excluded_paths"] == ["Windows", "VMs"]
    assert "named artifact" in store["logs"][-1]


@pytest.fixture
def review_api(monkeypatch, review_env):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.deps import firm_db
    from app.routers import extract_review as router_mod

    store, _ = review_env
    app = FastAPI()
    app.include_router(router_mod.router)
    user = type("U", (), {"email": "examiner@lab"})()
    for route in router_mod.router.routes:
        for dep in route.dependant.dependencies:
            app.dependency_overrides[dep.call] = lambda: user
    app.dependency_overrides[firm_db] = lambda: type("DB", (), {"commit": lambda self: None})()
    monkeypatch.setattr("app.routers.jobs._ensure_job", lambda db, job_id: {"id": job_id, "status": "paused"})
    resumed = []
    monkeypatch.setattr("app.routers.jobs.resume_job", lambda job_id, db, current: resumed.append(job_id) or {"status": "processing"})
    return TestClient(app), store, resumed


def test_review_endpoints_record_the_decision_and_resume(review_api):
    client, store, resumed = review_api
    assert client.post(f"/api/jobs/{JOB}/extract-review", json={"excluded_paths": ["VMs"]}).status_code == 409
    assert client.put(f"/api/jobs/{JOB}/extract-review/settings", json={"required": True}).json()["required"] is True
    store["ds"]["extract_review"].update({"status": "pending", "summary": {"folders": [
        {"path": "VMs", "bytes": 40 << 30, "files": 2, "depth": 1},
        {"path": "VMs/Win7", "bytes": 40 << 30, "files": 2, "depth": 2},
    ], "big_files": [{"path": "Users/alice/Downloads/backup.iso", "bytes": 3 << 30}]}})
    # Switching the review off while it is waiting is refused.
    assert client.put(f"/api/jobs/{JOB}/extract-review/settings", json={"required": False}).status_code == 409
    r = client.post(f"/api/jobs/{JOB}/extract-review",
                    json={"excluded_paths": ["VMs", "VMs/Win7", "Users/alice/Downloads/backup.iso", "../x"]})
    assert r.status_code == 200
    assert r.json()["excluded"] == ["VMs", "VMs/Win7", "Users/alice/Downloads/backup.iso"]
    assert r.json()["excluded_estimate_bytes"] == (40 << 30) + (3 << 30)  # nested folder not counted twice
    st = store["ds"]["extract_review"]
    assert st["status"] == "approved" and st["decided_by"] == "examiner@lab"
    assert resumed == [JOB] and "examiner@lab" in store["logs"][-1]


# ---------------------------------------------------------------------------
# Known-good (NSRL) files
# ---------------------------------------------------------------------------

def _sha(data: bytes, algo: str = "sha256") -> str:
    return hashlib.new(algo, data).hexdigest()


@pytest.fixture
def known_good_index(tmp_path, monkeypatch):
    from app.services import known_good_filter
    from app.services.extract_known_good import build_index

    source = tmp_path / "rds.txt"
    source.write_text("\n".join([_sha(b"kernel32"), _sha(b"notepad")]) + "\n")
    index = tmp_path / "nsrl-sha256.hgi"
    build_index(source, index, algorithm="sha256")
    monkeypatch.setenv("FORENSIC_KNOWN_GOOD_INDEX", str(index))
    monkeypatch.setattr(known_good_filter, "_cached", None)
    return index


def test_known_good_files_are_split_out_by_hash(known_good_index):
    from app.services.known_good_filter import split_known_good, status

    entries = [
        {"path": "Windows/System32/kernel32.dll", "size_bytes": 8, "sha256": _sha(b"kernel32")},
        {"path": "Users/alice/kernel32.dll", "size_bytes": 7, "sha256": _sha(b"dropper")},  # same name, other bytes
        {"path": "Windows/notepad.exe", "size_bytes": 7, "sha256": _sha(b"notepad")},
        {"path": "Users/alice/plan.docx", "size_bytes": 4, "sha256": ""},
    ]
    kept, known = split_known_good(entries)
    assert [e["path"] for e in kept] == ["Users/alice/kernel32.dll", "Users/alice/plan.docx"]
    assert [e["path"] for e in known] == ["Windows/System32/kernel32.dll", "Windows/notepad.exe"]
    assert status()["active"] is True and status()["hashes"] == 2


def test_a_wrong_algorithm_index_switches_the_filter_off(tmp_path, monkeypatch):
    from app.services import known_good_filter
    from app.services.extract_known_good import build_index

    src = tmp_path / "rds.txt"
    src.write_text(_sha(b"kernel32", "sha1") + "\n")
    build_index(src, tmp_path / "sha1.hgi", algorithm="sha1")
    monkeypatch.setenv("FORENSIC_KNOWN_GOOD_INDEX", str(tmp_path / "sha1.hgi"))
    monkeypatch.setattr(known_good_filter, "_cached", None)
    entries = [{"path": "a", "sha256": _sha(b"kernel32")}]
    assert known_good_filter.split_known_good(entries) == (entries, [])
    monkeypatch.setenv("FORENSIC_KNOWN_GOOD_INDEX", str(tmp_path / "missing.hgi"))
    assert known_good_filter.status()["active"] is False


def test_cli_builds_the_index_atomically(tmp_path, monkeypatch, capsys):
    from app.services import known_good_cli, known_good_filter

    src = tmp_path / "RDS.csv"
    src.write_text('"SHA-256","FileName"\n"' + _sha(b"kernel32").upper() + '","kernel32.dll"\n')
    out = tmp_path / "known-good" / "nsrl-sha256.hgi"
    monkeypatch.setenv("FORENSIC_KNOWN_GOOD_INDEX", str(out))
    monkeypatch.setattr(known_good_filter, "_cached", None)
    assert known_good_cli.main(["build", str(src)]) == 0
    assert out.is_file() and not out.with_suffix(".hgi.building").exists()
    assert known_good_cli.main(["status"]) == 0
    assert '"active": true' in capsys.readouterr().out


def test_manifest_lists_known_good_files_separately(known_good_index, monkeypatch):
    from app.services import extracted_disk

    stored = {}
    monkeypatch.setattr(extracted_disk, "put_bytes", lambda key, data, content_type=None: stored.setdefault(key, data) and f"s3://{key}")
    vd = type("VD", (), {"base_name": "laptop", "format": "ewf", "mode": "ewf", "segment_paths": [], "segment_hashes": {}})()
    settings = type("S", (), {"extract_zstd_level": 3})()
    filter_stats: dict = {"filtered_out": 0}
    index = [
        {"path": "Windows/notepad.exe", "size_bytes": 7, "sha256": _sha(b"notepad"), "part_id": 0, "offset": 0},
        {"path": "Users/alice/plan.docx", "size_bytes": 4, "sha256": _sha(b"plan"), "part_id": 0, "offset": 7},
    ]
    out = extracted_disk._finalize_manifest(
        job_id=JOB, vd=vd, nodes=[{}, {}], all_nodes=[{}, {}], all_index=index, part_uris=["p0"], total_files=2,
        total_bytes=11, total_skipped=0, mode="standard", filter_stats=filter_stats, payload_count=1, settings=settings,
    )
    import zstandard

    keys = {k.rsplit("/", 1)[-1]: k for k in stored}
    main_index = zstandard.ZstdDecompressor().decompress(stored[keys["index.jsonl.zst"]]).decode()
    assert "plan.docx" in main_index and "notepad.exe" not in main_index
    known = zstandard.ZstdDecompressor().decompress(stored[keys["known_good.jsonl.zst"]]).decode()
    assert "notepad.exe" in known
    assert out["manifest"]["known_good"]["files"] == 1 and filter_stats["known_good_hash"] == 1
