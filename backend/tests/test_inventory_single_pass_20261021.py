"""Artifact inventory (stage 9) single-pass behaviour — 2026-10-21.

The stall at "Normalize / correlate / artifact inventory" came from collectors
re-reading evidence that stage 5 had already parsed, each streaming multi-GB tar
shards separately and concurrently. These tests pin the replacement behaviour
without a database: fakes stand in for SQL and shard reads.
"""

from __future__ import annotations

import threading
import time

import pytest

from app.services import registry_evidence_index as rei

JOB = "11111111-1111-1111-1111-111111111111"


# ---------------------------------------------------------------- registry index
def _src(aid, path, sha=None, size=5_000_000):
    return {"id": aid, "file_path": path, "file_name": path.rsplit("/", 1)[-1], "size_bytes": size, "sha256": sha}


def test_select_sources_dedupes_vss_copies_and_prefers_parsed_copy():
    rows = [
        _src("a", "Windows/System32/config/SYSTEM", sha="AA"),
        _src("b", "System Volume Information/copy/SYSTEM", sha="aa"),  # same content
        _src("c", "Users/bob/NTUSER.DAT", sha=None),
        _src("d", "Users/eve/NTUSER.DAT", sha=None),
    ]
    chosen = rei.select_sources(rows, covered_ids={"b", "c"})
    assert [r["id"] for r in chosen] == ["b", "c", "d"]


class _FakeIndexDb:
    """Answers the three registry-index queries from canned data."""

    def __init__(self, sources, covered, stored):
        self.sources, self.covered, self.stored = sources, covered, stored
        self.calls = []

    def fetchall(self, _db, sql, params=None):
        self.calls.append(sql)
        if "FROM job_artifacts" in sql and "setupapi" in sql:
            return list(self.sources)
        if "SELECT DISTINCT job_artifact_id" in sql:
            return [{"aid": a} for a in self.covered if a in set(params["ids"])]
        if "WITH latest AS" in sql:
            return [r for r in self.stored if r["aid"] in set(params["ids"])]
        raise AssertionError(sql)


def _install(monkeypatch, fake, live=None):
    monkeypatch.setattr(rei, "fetchall", fake.fetchall)
    reads = []

    def fake_read(_db, _job, rows, max_bytes=None):
        reads.append([r["file_path"] for r in rows])
        return live or {}

    import app.services.artifact_live_counts as alc
    monkeypatch.setattr(alc, "_read_job_files", fake_read)
    rei.clear_registry_evidence_cache()
    return reads


def test_index_serves_stored_parse_records_without_any_shard_read(monkeypatch):
    sources = [
        _src("sys", "Windows/System32/config/SYSTEM", sha="s1"),
        _src("vss", "System Volume Information/x/SYSTEM", sha="s1"),
        _src("nt", "Users/alice/NTUSER.DAT", sha="n1"),
        _src("setup", "Windows/INF/setupapi.dev.log", sha="u1", size=90_000),
    ]
    stored = [
        {"aid": "sys", "rec": {"record_type": "usb_device", "bus": "USBSTOR", "class_id": "Disk&Ven_X", "serial": "1"}},
        {"aid": "vss", "rec": {"record_type": "usb_device", "bus": "USBSTOR", "class_id": "Disk&Ven_X", "serial": "1"}},
        {"aid": "nt", "rec": {"record_type": "rdp_connection", "host": "10.0.0.5", "user": "alice"}},
        {"aid": "nt", "rec": {"record_type": "feature_usage", "metric": "app_launch", "entry_count": 7,
                              "key_path": "Software\\FeatureUsage\\AppLaunch"}},
        {"aid": "setup", "rec": {"record_type": "usb_usage_event", "device_id": "USB\\VID_0781&PID_5567\\ABC"}},
    ]
    fake = _FakeIndexDb(sources, covered={"sys", "vss", "nt", "setup"}, stored=stored)
    reads = _install(monkeypatch, fake)
    idx = rei.registry_evidence(object(), JOB)
    assert reads == [], "all sources parsed in stage 5 -> no shard reads"
    assert len(list(idx.records("usb_device"))) == 1, "VSS duplicate counted once"
    assert [k for _, k, _ in idx.records("rdp_connection")] == ["ntuser"]
    assert [k for _, k, _ in idx.records("usb_usage_event")] == ["setupapi"]
    assert idx.stats["live_fallback_sources"] == 0


def test_index_reads_only_unparsed_hives_live_in_one_call(monkeypatch):
    sources = [
        _src("ok", "Users/alice/NTUSER.DAT", sha="n1"),
        _src("timeout", "Users/bob/NTUSER.DAT", sha="n2"),
    ]
    stored = [{"aid": "ok", "rec": {"record_type": "rdp_connection", "host": "srv1"}}]
    fake = _FakeIndexDb(sources, covered={"ok"}, stored=stored)
    import app.parsers.registry as reg
    monkeypatch.setattr(reg, "parse_registry_hive",
                        lambda data, path: [{"record_type": "rdp_connection", "host": "srv2"}])
    reads = _install(monkeypatch, fake, live={"Users/bob/NTUSER.DAT": b"regf" + b"\0" * 8000})
    idx = rei.registry_evidence(object(), JOB)
    assert reads == [["Users/bob/NTUSER.DAT"]]
    assert sorted(r["host"] for _, _, r in idx.records("rdp_connection")) == ["srv1", "srv2"]
    assert idx.stats["live_fallback_sources"] == 1


def test_index_is_single_flight_across_parallel_collectors(monkeypatch):
    builds = []

    def slow_build(_db, job_id):
        builds.append(job_id)
        time.sleep(0.2)
        return rei.RegistryEvidence()

    monkeypatch.setattr(rei, "build_registry_evidence", slow_build)
    rei.clear_registry_evidence_cache()
    threads = [threading.Thread(target=rei.registry_evidence, args=(object(), JOB)) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert builds == [JOB]


# ---------------------------------------------------------------- collectors on the index
def _index_with(records):
    idx = rei.RegistryEvidence()
    for rtype, path, kind, rec in records:
        idx.add(rtype, path, kind, {"record_type": rtype, **rec})
    return idx


def test_usb_rdp_feature_usage_collectors_read_the_index(monkeypatch):
    from app.services import catalog_aligned_counts as cac

    idx = _index_with([
        ("usb_device", "Windows/System32/config/SYSTEM", "system", {"bus": "USBSTOR", "class_id": "A", "serial": "1"}),
        ("usb_device", "Windows/System32/config/SYSTEM", "system", {"bus": "USBSTOR", "class_id": "A", "serial": "1"}),
        ("usb_usage_event", "Windows/INF/setupapi.dev.log", "setupapi", {"device_id": "USB\\VID_0781&PID_5567\\X"}),
        ("usb_usage_event", "Windows/INF/setupapi.dev.log", "setupapi", {"device_id": "PCI\\VEN_8086"}),
        ("rdp_connection", "Users/a/NTUSER.DAT", "ntuser", {"host": "srv1", "user": "a"}),
        ("rdp_connection", "Users/a/NTUSER.DAT", "ntuser", {"host": "Software\\Microsoft\\Terminal Server Client\\AddIns"}),
        ("feature_usage", "Users/a/NTUSER.DAT", "ntuser", {"metric": "app_launch", "entry_count": 5,
                                                        "key_path": "Software\\x\\FeatureUsage\\AppLaunch"}),
        ("feature_usage", "Users/a/NTUSER.DAT", "ntuser", {"metric": "app_launch_switched", "entry_count": 99}),
    ])
    monkeypatch.setattr(rei, "registry_evidence", lambda _db, _job: idx)
    monkeypatch.setattr(cac, "_usb_devices_from_parse_results", lambda *a, **k: None)
    count, devices = cac.count_usb_device_records(object(), JOB)
    assert count == 2 and {d.get("bus") for d in devices} == {"USBSTOR", "SetupAPI"}
    assert cac.count_rdp_connection_records(object(), JOB)[0] == 1
    assert cac.count_feature_usage_records(object(), JOB) == 5


def test_installed_programs_read_the_index(monkeypatch):
    from app.services import artifact_live_counts as alc

    idx = _index_with([
        ("installed_program", "Windows/System32/config/SOFTWARE", "software",
         {"display_name": "Microsoft Office", "is_microsoft": True, "uninstall_key": "k1"}),
        ("installed_program", "Windows/System32/config/SOFTWARE", "software",
         {"display_name": "7-Zip", "is_microsoft": False, "uninstall_key": "k2"}),
        ("installed_program", "Users/a/NTUSER.DAT", "ntuser",
         {"display_name": "Zoom", "is_microsoft": False, "uninstall_key": "k3"}),
    ])
    monkeypatch.setattr(rei, "registry_evidence", lambda _db, _job: idx)
    inv = alc.scan_registry_inventory(object(), JOB)
    assert (inv["microsoft_count"], inv["non_microsoft_count"]) == (1, 2)


# ---------------------------------------------------------------- bulk shard reads
def test_iter_job_file_contents_streams_each_shard_once(monkeypatch):
    from app.services import artifact_live_counts as alc
    import app.services.tar_cache as tc

    monkeypatch.setattr(alc, "_job_index_map", lambda _db, _job: {
        "u/a.eml": "s3://p1", "u/b.eml": "s3://p1", "u/c.eml": "s3://p2"})
    passes = []

    def fake_iter(part, paths, max_bytes=None):
        passes.append((part, sorted(paths)))
        for p in sorted(paths):
            yield p, b"data:" + p.encode()

    monkeypatch.setattr(tc, "iter_files_from_part", fake_iter)
    rows = [{"file_path": "u/a.eml"}, {"file_path": "u/b.eml"}, {"file_path": "u/c.eml"},
            {"file_path": "x.eml", "minio_uri": "s3://obj"}]
    out = list(alc.iter_job_file_contents(object(), JOB, rows))
    assert passes == [("s3://p1", ["u/a.eml", "u/b.eml"]), ("s3://p2", ["u/c.eml"])]
    resolved = {r["file_path"]: ok for r, _, ok in out}
    assert resolved == {"u/a.eml": True, "u/b.eml": True, "u/c.eml": True, "x.eml": False}


def test_read_job_files_capped_merges_groups_into_one_pass(monkeypatch):
    from app.services import artifact_live_counts as alc
    import app.services.tar_cache as tc

    monkeypatch.setattr(alc, "_job_index_map", lambda _db, _job: {"h/History": "p1", "d/x.url": "p1"})
    passes = []

    def fake_iter(part, paths, max_bytes_by_path=None):
        passes.append((part, dict(max_bytes_by_path)))
        for p in paths:
            yield p, b"x"

    monkeypatch.setattr(tc, "iter_files_from_part", fake_iter)
    out = alc.read_job_files_capped(object(), JOB, [([{"file_path": "h/History"}], 100), ([{"file_path": "d/x.url"}], 10)])
    assert passes == [("p1", {"h/History": 100, "d/x.url": 10})]
    assert set(out) == {"h/History", "d/x.url"}


# ---------------------------------------------------------------- email aggregate
def test_email_record_types_are_counted_in_one_aggregate(monkeypatch):
    from app.services import email_inventory as ei

    calls = []

    def fake_counts(_db, job_id, types):
        calls.append(tuple(types))
        return {"outlook_message": 4, "windows_mail_message": 2}

    monkeypatch.setattr(ei, "_parsed_record_counts", fake_counts)
    ei.clear_parsed_record_count_cache()
    got = [ei._count_parsed_records(object(), JOB, record_type=t) for t in
           ("outlook_message", "windows_mail_message", "outlook_task", "outlook_contact",
            "outlook_appointment", "email_attachment", "windows_mail")]
    assert got == [4, 2, 0, 0, 0, 0, 0]
    assert len(calls) == 1, "one pass over parse results for every email/calendar type"


# ---------------------------------------------------------------- MIME scan
def test_mime_scan_is_single_flight_per_job(monkeypatch):
    from app.services import email_mime_inventory as emi

    runs = []

    def slow_impl(_db, job_id, **_kw):
        runs.append(job_id)
        time.sleep(0.2)
        result = {"message_occurrences": 1}
        emi._JOB_SCAN_CACHE[job_id] = result
        return dict(result)

    monkeypatch.setattr(emi, "_scan_job_email_mime_inventory_impl", slow_impl)
    emi.clear_email_mime_scan_cache()
    threads = [threading.Thread(target=emi.scan_job_email_mime_inventory, args=(object(), JOB)) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert runs == [JOB]


def test_extensionless_gate_still_rejects_non_rfc822_bytes():
    from app.services import email_mime_inventory as emi

    info, failed = emi._scan_message_bytes(object(), JOB, {"file_path": "Users/a/AppData/Local/x/LOCK"},
                                           b"\x00\x01binary", extensionless_candidate=True)
    assert info is None and failed is False


# ---------------------------------------------------------------- URL zero-count bug
def test_disk_job_with_empty_priority_table_reads_browser_history_live(monkeypatch):
    """Disk priority scan was removed; an empty table must not mean 'no URLs'."""
    from app.services import browser_url_inventory as bui
    import app.services.forensic_priority_evidence as fpe
    import app.services.forensic_serial_policy as fsp
    import app.services.artifact_live_counts as alc

    monkeypatch.setattr(bui, "_persisted_browser_visits", lambda _db, _job: [])
    monkeypatch.setattr(fsp, "serial_enabled", lambda: True)
    monkeypatch.setattr(fpe, "priority_record_table", lambda _db, _job: "forensic_priority_records")

    def fake_fetchall(_db, sql, params=None):
        if "forensic_priority_records" in sql:
            return []  # disk jobs: no browser rows any more
        if sql is bui._BROWSER_SOURCE_SQL:
            return [{"file_path": "Users/a/AppData/Local/Google/Chrome/User Data/Default/History", "size_bytes": 9000}]
        return []

    monkeypatch.setattr(bui, "fetchall", fake_fetchall)
    monkeypatch.setattr(bui, "fetchone", lambda _db, sql, params=None: {"name": "pipeline_stage_runs", "ok": 1})
    monkeypatch.setattr(alc, "read_job_files_capped", lambda _db, _job, groups: {
        "Users/a/AppData/Local/Google/Chrome/User Data/Default/History": b"S" * 1024})
    monkeypatch.setattr(bui, "extract_url_records_from_sqlite",
                        lambda data, path: [{"url": "https://web.whatsapp.com/", "visit_count": 3}])
    bui.clear_browser_url_cache(JOB)
    records = bui.collect_job_browser_url_records(object(), JOB)
    assert [r["url"].rstrip("/") for r in records] == ["https://web.whatsapp.com"]
