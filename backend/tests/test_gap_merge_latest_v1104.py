"""V1.10.4: Merge gap reports — From and To both editable; no dates = latest 20 reports."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.routers import cases as cases_router
from app.routers.cases import gap_merge_filter_window

TODAY = date(2026, 10, 16)


def test_no_dates_means_no_date_filter():
    assert gap_merge_filter_window(None, None) == (None, None)
    assert gap_merge_filter_window("", "  ") == (None, None)


def test_from_and_to_are_independent_and_editable():
    assert gap_merge_filter_window("2026-10-01", None) == (date(2026, 10, 1), None)
    assert gap_merge_filter_window(None, "2026-10-10") == (None, date(2026, 10, 10))
    # To is no longer forced to today: a past range works.
    assert gap_merge_filter_window("2026-09-01", "2026-09-30") == (date(2026, 9, 1), date(2026, 9, 30))
    assert gap_merge_filter_window("2026-10-05", "2026-10-05") == (date(2026, 10, 5), date(2026, 10, 5))


def test_invalid_dates_and_reversed_range_are_rejected():
    with pytest.raises(HTTPException) as bad:
        gap_merge_filter_window("16-10-2026", None)
    assert bad.value.status_code == 400 and bad.value.detail["error"]["code"] == "invalid_date"
    with pytest.raises(HTTPException) as bad_to:
        gap_merge_filter_window(None, "yesterday")
    assert "to_date" in bad_to.value.detail["error"]["message"]
    with pytest.raises(HTTPException) as reversed_range:
        gap_merge_filter_window("2026-10-16", "2026-10-01")
    assert reversed_range.value.detail["error"]["code"] == "invalid_date_range"


def _case_rows(n: int, *, blank_every: int = 0):
    rows = []
    for i in range(n):
        created = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc) - timedelta(days=i)
        site = {"client_name": f"Client {i}", "author": "Bhagyesh Sawant"}
        if blank_every and i % blank_every == 0:
            site = {"client_name": "  "}  # saved but empty: never listed
        rows.append({"id": f"00000000-0000-0000-0000-{i:012d}", "title": f"Case {i}", "status": "open",
                     "created_at": created, "created_ist_date": created.date(), "gap_site_json": site})
    return rows


def _call(monkeypatch, rows, total, **query):
    sql_seen = []

    def fake_fetchone(db, sql, params=None):
        sql_seen.append(("one", sql, dict(params or {})))
        return {"c": total}

    def fake_fetchall(db, sql, params=None):
        sql_seen.append(("all", sql, dict(params or {})))
        return rows[: params["fetch_lim"]]

    monkeypatch.setattr(cases_router, "fetchone", fake_fetchone)
    monkeypatch.setattr(cases_router, "fetchall", fake_fetchall)
    monkeypatch.setattr(cases_router, "_ensure_default_workspace", lambda *a, **k: None)
    monkeypatch.setattr(cases_router, "apply_firm_search_path", lambda *a, **k: None)
    monkeypatch.setattr(cases_router, "_ist_today", lambda: TODAY)
    import app.services.gap_assessment_report as gap

    monkeypatch.setattr(gap, "ensure_gap_site_column", lambda db: None)
    args = {"from_date": None, "to_date": None, "limit": None}
    args.update(query)
    out = cases_router.list_gap_merge_candidates(**args, db=object(), current=SimpleNamespace(schema_name="firm_x"))
    return out, sql_seen


def test_default_lists_latest_20_newest_first(monkeypatch):
    out, sql = _call(monkeypatch, _case_rows(57), 57)
    assert out["filtered"] is False and out["limit"] == 20 and out["total"] == 20
    assert out["from_date"] is None and out["to_date"] is None
    assert out["total_matching"] == 57 and out["has_more"] is True
    assert [i["title"] for i in out["items"][:3]] == ["Case 0", "Case 1", "Case 2"]
    assert out["items"][0]["day_label"] == "today" and out["items"][1]["day_label"] == "yesterday"
    list_sql = sql[1][1]
    assert "ORDER BY c.created_at DESC" in list_sql and ":from_d" not in list_sql and ":to_d" not in list_sql


def test_blank_site_overviews_do_not_shorten_the_latest_20(monkeypatch):
    out, _ = _call(monkeypatch, _case_rows(60, blank_every=3), 60)
    assert out["total"] == 20
    assert all(i["gap_details"].get("client_name", "").startswith("Client") for i in out["items"])


def test_date_range_filters_both_ends_and_lists_up_to_200(monkeypatch):
    out, sql = _call(monkeypatch, _case_rows(5), 5, from_date="2026-10-12", to_date="2026-10-14")
    assert out["filtered"] is True and out["limit"] == 200
    assert out["from_date"] == "2026-10-12" and out["to_date"] == "2026-10-14"
    count_sql, count_params = sql[0][1], sql[0][2]
    assert ">= CAST(:from_d AS date)" in count_sql and "<= CAST(:to_d AS date)" in count_sql
    assert count_params == {"from_d": "2026-10-12", "to_d": "2026-10-14"}
    # day labels are relative to the real today, not to the chosen To date
    assert out["items"][2]["day_label"] == "14 Oct 2026"


def test_only_to_date_and_explicit_limit(monkeypatch):
    out, sql = _call(monkeypatch, _case_rows(30), 30, to_date="2026-10-10", limit=5)
    assert out["limit"] == 5 and out["total"] == 5 and out["from_date"] is None
    assert ":from_d" not in sql[0][1] and "<= CAST(:to_d AS date)" in sql[0][1]
