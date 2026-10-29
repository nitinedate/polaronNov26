from __future__ import annotations

from lxml import etree

from agent import gmp_local


def test_feed_count_supports_info_count_schema():
    xml = etree.fromstring(
        b"<get_info_response><info_count><filtered>54321</filtered><total>54321</total></info_count></get_info_response>"
    )
    assert gmp_local._feed_count_from_xml(xml) == 54321


def test_feed_health_never_requests_the_full_nvt_list(monkeypatch):
    """V1.9.4: get_nvts(extended=True) is sent as a bare <get_nvts/> (filter dropped),
    which made gvmd return all ~185k checks on every probe (~40 s each)."""
    class FakeGmp:
        def __init__(self):
            self.calls = []

        def get_feeds(self):
            return etree.fromstring(b"<get_feeds_response><feed><version>20261002</version></feed></get_feeds_response>")

        def get_nvts(self, **kwargs):
            self.calls.append(kwargs)
            return etree.fromstring(
                b"<get_info_response><info id='1'/><info_count><filtered>185633</filtered>"
                b"<page>1</page></info_count></get_info_response>"
            )

    gmp = FakeGmp()
    health = gmp_local._feed_health(gmp)
    assert gmp.calls == [{"filter_string": "rows=1 first=1"}]
    assert not any(c.get("extended") for c in gmp.calls)
    assert health["nvt_count"] == 185633


def test_feed_health_falls_back_to_family_totals_not_the_full_list(monkeypatch):
    class FakeGmp:
        def __init__(self):
            self.calls = []

        def get_feeds(self):
            return etree.fromstring(b"<get_feeds_response/>")

        def get_nvts(self, **kwargs):
            self.calls.append(kwargs)
            return etree.fromstring(b"<get_info_response><info id='1'/></get_info_response>")  # no count

        def get_nvt_families(self):
            return etree.fromstring(
                b"<r><families><family><name>A</name><max_nvt_count>100000</max_nvt_count></family>"
                b"<family><name>B</name><max_nvt_count>85633</max_nvt_count></family></families></r>"
            )

    gmp = FakeGmp()
    health = gmp_local._feed_health(gmp)
    assert health["nvt_count"] == 185633
    assert not any(c.get("extended") for c in gmp.calls)


def test_unknown_total_with_feed_version_is_positive_inventory_evidence(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    monkeypatch.setattr(
        gmp_local,
        "_feed_health",
        lambda gmp, config_id=None: {
            "syncing": False,
            "versions": ["202609290606"],
            "nvt_count": -1,
            "config_nvt_count": None,
        },
    )
    state = gmp_local._ospd_feed_state(object())
    assert state["ready"] is True
    assert state["reason"] == "nvt_inventory_present_count_unavailable"
    assert state["count_trustworthy"] is False


def test_unknown_total_without_feed_version_stays_fail_closed(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    monkeypatch.setattr(
        gmp_local,
        "_feed_health",
        lambda gmp, config_id=None: {
            "syncing": False,
            "versions": [],
            "nvt_count": -1,
            "config_nvt_count": None,
        },
    )
    state = gmp_local._ospd_feed_state(object())
    assert state["ready"] is False
    assert state["reason"] == "nvt_count_unavailable"
