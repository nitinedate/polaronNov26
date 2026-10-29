"""Regression tests for the Windows PowerShell -> OSPd Python stdin fix."""
from pathlib import Path
import json
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "scripts" / "ospd-network-probe.py"
WRAPPER = ROOT / "Test-Target-Network.ps1"


def _probe(*args):
    return subprocess.run([sys.executable, "-", *args], input=PROBE.read_text(),
                          capture_output=True, text=True, timeout=20)


def test_python_stdin_probe_can_detect_local_listener():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        result = _probe("127.0.0.1", "--ports", str(port), "--timeout", "0.25")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["source"] == "ospd_container_tcp_connect"
    assert data["open_ports"] == [port]
    assert data["vulnerability_checks_verified"] is False


def test_invalid_inputs_cannot_expand_to_a_subnet():
    for addr, ports in [("192.0.2.0/24", "443"), ("127.0.0.1", "1-65535"),
                        ("127.0.0.1", "0"), ("127.0.0.1", "443;whoami")]:
        result = _probe(addr, "--ports", ports)
        assert result.returncode != 0


def test_parses_range_without_claiming_vulnerabilities():
    result = _probe("127.0.0.1", "--ports", "1-3,2", "--timeout", "0.2")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["ports_checked"] == [1, 2, 3]
    assert data["vulnerability_checks_verified"] is False


def test_powershell_exec_uses_stdin_not_fragile_c_string():
    script = WRAPPER.read_text()
    assert '$ospdScript | docker compose exec -T ospd-openvas python3 - $TargetIP' in script
    assert 'python3 -c $py' not in [line.strip() for line in script.splitlines()]
    assert 'Find-NetRoute' in script
    assert 'Get-NetNeighbor' in script
    assert '--ports $normalizedPorts' in script
