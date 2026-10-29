"""V1.10.0 — the agent tells the central server which laptop it is.

All laptops of one user bind the same emailed token; the central server could not tell
them apart and Laptop-DESKTOP-J19GUGP stayed "offline" while Laptop-NITIN received all
heartbeats. Every agent request and the Start-Laptop binding now carry the Windows
computer name (and the configured scanner name) next to the per-install instance id."""
from __future__ import annotations

from agent import bootstrap_control_plane as boot
from agent.api_client import CentralApi
from agent.laptop_identity import clean_computer_name, computer_name, identity_headers


def test_live_windows_name_wins_over_a_possibly_copied_env_value(monkeypatch):
    monkeypatch.setenv("AGENT_COMPUTER_NAME", "NITIN")          # .env copied from the other laptop
    monkeypatch.setenv("HOST_COMPUTERNAME", "DESKTOP-J19GUGP")  # compose: this PC's COMPUTERNAME
    assert computer_name() == "DESKTOP-J19GUGP"
    monkeypatch.setenv("HOST_COMPUTERNAME", "")                 # compose run without COMPUTERNAME
    assert computer_name() == "NITIN"


def test_names_are_reduced_to_header_safe_text():
    assert clean_computer_name(" DESKTOP-J19GUGP\r\n") == "DESKTOP-J19GUGP"
    assert clean_computer_name("PC naïve/../x") == "PCnave..x"
    h = identity_headers("inst-1", scanner_name="Laptop – NITIN", computer="NITIN")
    assert h == {"X-Aetheris-Agent-Instance": "inst-1", "X-Aetheris-Agent-Computer": "NITIN",
                 "X-Aetheris-Agent-Name": "Laptop  NITIN"}


def test_every_central_request_carries_the_laptop_identity(monkeypatch, tmp_path):
    monkeypatch.setenv("HOST_COMPUTERNAME", "DESKTOP-J19GUGP")
    monkeypatch.setenv("SCANNER_NAME", "")
    monkeypatch.setenv("AGENT_INSTANCE_ID", "inst-j19")
    api = CentralApi(base_url="https://central.example", tenant="p", token="tok")
    assert api.headers["X-Aetheris-Agent-Computer"] == "DESKTOP-J19GUGP"
    assert api.headers["X-Aetheris-Agent-Instance"] == "inst-j19"
    assert "X-Aetheris-Agent-Name" not in api.headers


def test_bind_sends_computer_and_instance_and_heartbeats_as_this_laptop(monkeypatch):
    calls = []
    monkeypatch.setattr(boot, "preflight", lambda base, tenant, verify: {"ok": True, "canonical_url": "https://c"})

    def fake_request(method, url, tenant, **kw):
        calls.append((url, kw))
        if url.endswith("/api/auth/token-login"):
            return 200, "{}", {"access_token": "acc"}, url
        if url.endswith("/bind-client-token"):
            return 200, "{}", {"id": "sid-j19", "agent_token": "tok"}, url
        return 200, "{}", {}, url

    monkeypatch.setattr(boot, "_request_json", fake_request)
    monkeypatch.setattr(boot, "_extract_access_token", lambda data: data.get("access_token"))
    out = boot.bind("https://c", "p", "tok", "Laptop-DESKTOP-J19GUGP", "portable", "sid-copied-from-nitin", True,
                    computer_name="DESKTOP-J19GUGP", agent_instance_id="inst-j19")
    assert out["ok"] and out["scanner_id"] == "sid-j19"
    bind_kw = next(kw for url, kw in calls if url.endswith("/bind-client-token"))
    assert bind_kw["body"]["computer_name"] == "DESKTOP-J19GUGP"
    assert bind_kw["body"]["agent_instance_id"] == "inst-j19"
    hb_kw = next(kw for url, kw in calls if url.endswith("/heartbeat"))
    assert hb_kw["extra_headers"]["X-Aetheris-Agent-Computer"] == "DESKTOP-J19GUGP"
    assert hb_kw["extra_headers"]["X-Aetheris-Agent-Instance"] == "inst-j19"


def test_bind_cli_accepts_the_new_arguments(monkeypatch):
    seen = {}
    monkeypatch.setattr(boot, "bind", lambda *a, **k: seen.update(k) or {"ok": True})
    monkeypatch.setattr(boot, "_emit", lambda payload, code: code)
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("tok\n"))
    rc = boot.main(["bind", "--base-url", "https://c", "--tenant", "p", "--scanner-name", "Laptop-X",
                    "--computer-name", "DESKTOP-J19GUGP", "--agent-instance-id", "inst-j19"])
    assert rc == 0 and seen == {"computer_name": "DESKTOP-J19GUGP", "agent_instance_id": "inst-j19"}
