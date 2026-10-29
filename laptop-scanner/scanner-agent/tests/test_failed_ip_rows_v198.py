"""V1.9.8 — field job fcbb90c0 (10 IPs): one IP failed mid-scan and its partial findings
were kept, but declared as 0 results. The job uploaded 291 rows while declaring 241, so
the central integrity check failed the whole job. Kept rows are now declared."""
from __future__ import annotations

import copy

from tests.test_speed_v167 import _done, _loop

BAD = "192.168.1.239"
GOOD = ["192.168.1.10", "192.168.1.11"]


def _rows(host, n):
    return [{"result_id": f"{host}-{i}", "host": host, "name": f"check {i}", "severity": 5.0} for i in range(n)]


def _good(host):
    d = copy.deepcopy(_done(host))
    d["vulnerabilities"] = _rows(host, 10)
    d["evidence"]["report_result_count"] = 10
    return d


def _poll(declared_for_bad):
    def poll(host, n, stopped):
        if host == BAD and n >= 3:
            return {"status": "failed", "gmp_status": "interrupted", "progress": 61,
                    "vulnerabilities": _rows(host, 50),
                    "evidence": {"report_id": "rep-bad", "task_status": "interrupted",
                                 "report_result_count": declared_for_bad}}
        return _good(host) if n >= 3 else {"status": "running", "gmp_status": "running", "progress": 30,
                                          "vulnerabilities": [], "evidence": {}}
    return poll


def test_kept_rows_of_a_failed_ip_are_declared():
    import pytest
    mp = pytest.MonkeyPatch()
    try:
        uploaded, events, _, _ = _loop(mp, GOOD + [BAD], _poll(50))
    finally:
        mp.undo()
    final = uploaded[-1]
    assert len(final["vulnerabilities"]) == 70
    assert final["report_result_count"] == 70  # 10 + 10 + the 50 kept rows of the failed IP
    assert any(s.get("host") == BAD for s in final.get("skipped_hosts") or []) or BAD not in final.get("assessed_hosts", [])


def test_kept_rows_without_a_declared_count_declare_what_was_kept(monkeypatch):
    uploaded, _, _, _ = _loop(monkeypatch, GOOD + [BAD], _poll(0))
    final = uploaded[-1]
    assert final["report_result_count"] == len(final["vulnerabilities"]) == 70
