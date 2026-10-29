"""V1.10.10: newly attached HDD / SSD / USB drives are detected quickly and automatically."""
from __future__ import annotations

from pathlib import Path

import app.services.hostdrive_agent as hda

ROOT = Path(__file__).resolve().parents[2]


def _helper_text() -> str:
    return (ROOT / "scripts" / "host-drive-helper.ps1").read_text(encoding="utf-8", errors="replace")


def test_helper_answers_drives_on_its_accept_thread_from_the_drive_table():
    text = _helper_text()
    assert 'else if (method == "GET" && path == "/drives") WriteDrives(ctx);' in text
    assert 'path == "/refresh-drive-mounts"' in text
    accept = text.split("void AcceptLoop()", 1)[1].split("static string JsonStr", 1)[0]
    assert accept.index('path == "/drives"') < accept.index("else Queue.Add(ctx);")
    assert accept.index('path == "/refresh-drive-mounts"') < accept.index("else Queue.Add(ctx);")
    fast = text.split("static string JsonEsc(string s)", 1)[1].split("void WriteMobileDevices(HttpListenerContext ctx)", 1)[0]
    assert "Environment.GetLogicalDrives()" in fast and "new DriveInfo(root)" in fast
    assert "Get-Volume" not in fast and "Win32_LogicalDisk" not in fast  # no WMI / Storage cmdlets
    assert "Task.WaitAll(tasks.ToArray(), detailTimeoutMs)" in fast  # one stuck device cannot hold the answer
    assert "if (t != DriveType.Network)" in fast  # never touch a possibly disconnected share
    assert "X-Host-Helper-Token" in fast and "$dispatcher.ExpectedToken = [string]$expectedToken" in text
    # The C# sits in an expandable PowerShell here-string: the new code must not contain "$".
    assert "$" not in fast


def test_backend_waits_long_enough_and_flags_a_startup_only_list(monkeypatch):
    calls = []

    def fake_http_json(url, timeout):
        calls.append((url, timeout))
        if url.endswith("/health"):
            return {"ok": True}
        raise TimeoutError("timed out")

    monkeypatch.setattr(hda, "_helper_bases", lambda: ["http://host.docker.internal:9876"])
    monkeypatch.setattr(hda, "_http_json", fake_http_json)
    import app.services.drive_mount_agent as dma

    monkeypatch.setattr(dma, "mounted_letters", lambda: ["C", "D", "E", "F"])
    monkeypatch.setattr(dma, "inspect_host_letters", lambda: [{"letter": l, "mounted": True} for l in "CDEF"])
    out = hda.proxy_drives()
    assert [t for u, t in calls if u.endswith("/drives")] == [6.0]
    assert out["drives"] == ["C", "D", "E", "F"]
    assert out["partial"] is True and "mounted at startup only" in out["message"]


def test_backend_uses_the_helper_list_including_a_new_drive(monkeypatch):
    vols = [{"letter": l, "label": "Local Disk", "drive_type": "fixed"} for l in "CDEF"]
    vols.append({"letter": "G", "label": "New Volume", "drive_type": "removable"})

    def fake_http_json(url, timeout):
        if url.endswith("/health"):
            return {"ok": True}
        return {"ok": True, "source": "helper_fast", "drives": [v["letter"] for v in vols], "volumes": vols}

    monkeypatch.setattr(hda, "_helper_bases", lambda: ["http://host.docker.internal:9876"])
    monkeypatch.setattr(hda, "_http_json", fake_http_json)
    import app.services.drive_mount_agent as dma

    monkeypatch.setattr(dma, "mounted_letters", lambda: ["C", "D", "E", "F"])
    out = hda.proxy_drives()
    assert out["drives"] == ["C", "D", "E", "F", "G"] and out["partial"] is False
    g = [v for v in out["volumes"] if v["letter"] == "G"][0]
    assert g["mounted"] is False and g["label"] == "New Volume"  # browsable now, mounted only for extraction
    assert out["drives_source"] == "helper_fast"


def test_dialog_polls_while_open_and_announces_new_drives():
    src = (ROOT / "frontend" / "src" / "components" / "forensic" / "BrowseFolderDialog.tsx").read_text(encoding="utf-8")
    assert "const DRIVE_POLL_MS = 3000;" in src
    assert "window.setInterval(() => void pollDrives(), DRIVE_POLL_MS)" in src
    assert "New drive detected:" in src and "appear here automatically" in src
    assert "if (key === volumesKey.current) return;" in src  # no re-render when nothing changed
    assert "manualBusy.current" in src and "pollBusy.current" in src
