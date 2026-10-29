"""V1.9.9 — field job fcbb90c0 after Resume: the first attempt assessed 9 of 10 IPs;
Resume scanned only 192.168.1.239 (assessed IPs are not rescanned) and the upload said
"assessed 1 of 10" with the nine finished IPs as missing. IPs assessed by the earlier
attempt of the same job now count as assessed."""
from __future__ import annotations

import copy

from agent import main
from tests.test_speed_v167 import _done

TARGETS = [f"192.168.1.{n}" for n in (5, 6, 10, 11, 30, 51, 76, 192, 248, 239)]
RESUMED = "192.168.1.239"
EARLIER = [t for t in TARGETS if t != RESUMED]


def _merge(prior):
    details = copy.deepcopy(_done(RESUMED))
    return main._merge_chunk_details([([RESUMED], details)], all_targets=TARGETS, skipped_hosts=[],
                                     prior_assessed=prior)


def test_resume_counts_ips_assessed_by_the_earlier_attempt():
    ev = _merge(EARLIER)["evidence"]
    assert sorted(ev["assessed_hosts"]) == sorted(TARGETS)
    assert ev["hosts_assessed"] == 10
    assert ev["assessed_in_earlier_attempt"] == sorted(EARLIER)
    assert ev.get("missing_ip_targets") == []


def test_without_earlier_attempt_the_job_is_still_incomplete():
    ev = _merge(None)["evidence"]
    assert ev["hosts_assessed"] == 1
    assert sorted(ev.get("missing_ip_targets") or []) == sorted(EARLIER)


def test_hosts_outside_this_jobs_targets_are_ignored():
    ev = _merge(EARLIER + ["10.9.9.9"])["evidence"]
    assert "10.9.9.9" not in ev["assessed_hosts"]
    assert "10.9.9.9" not in ev["assessed_in_earlier_attempt"]
