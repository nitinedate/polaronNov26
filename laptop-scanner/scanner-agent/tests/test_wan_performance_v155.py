"""WAN retries must not block local Greenbone polling or leak HTTP sessions."""
from __future__ import annotations

import logging
import threading
import time

import httpx
import pytest

from agent.api_client import CentralApi
from agent.main import _patch_job_best_effort
from agent.log_shipper import CentralLogHandler


def test_http_timeouts_are_bounded_by_default(monkeypatch):
    monkeypatch.delenv("CENTRAL_API_TIMEOUT_SEC", raising=False)
    monkeypatch.delenv("CENTRAL_API_CONNECT_TIMEOUT_SEC", raising=False)
    api = CentralApi(base_url="https://example.test", tenant="a", token="t")
    try:
        value = api._httpx_timeout()
        assert value.connect == 4.0
        assert value.read == 15.0
        assert value.write == 15.0
    finally:
        api.close()


def test_progress_patch_uses_one_request_no_retry_sleep(monkeypatch):
    api = CentralApi(base_url="https://example.test", tenant="a", token="t")
    calls = []

    def lost_connection(*args, **kwargs):
        calls.append(args)
        raise httpx.ConnectTimeout("simulated unreachable API")

    monkeypatch.setattr(api._client, "request", lost_connection)
    monkeypatch.setattr("agent.api_client.time.sleep", lambda *a: pytest.fail("status update slept"))
    try:
        with pytest.raises(httpx.ConnectTimeout):
            api.patch_job("job", {"status": "running"})
        assert len(calls) == 1
        assert api._client is not None
    finally:
        api.close()


def test_failed_patch_never_stops_active_scan():
    class OfflineApi:
        def patch_job(self, *_a, **_kw):
            raise httpx.ConnectTimeout("central offline")
    assert _patch_job_best_effort(OfflineApi(), "job", {"status": "running"}) is False


def test_async_log_shipper_does_not_block_dispatch():
    started = threading.Event()
    release = threading.Event()

    class SlowApi:
        def post_logs(self, items):
            started.set()
            release.wait(1)
            return {}

    handler = CentralLogHandler(SlowApi())
    record = logging.LogRecord("scanner_agent.test", logging.INFO, "", 1, "message", (), None)
    handler.emit(record)
    t0 = time.monotonic()
    handler.maybe_flush_async(force=True)
    assert time.monotonic() - t0 < 0.5
    try:
        assert started.wait(1)
    finally:
        release.set()
