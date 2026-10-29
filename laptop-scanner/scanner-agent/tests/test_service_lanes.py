"""Four service lanes per IP, without dropping ports from a full sweep."""

from agent.service_lanes import lanes_for_port_range, merge_service_lane_polls, service_parallelism
from agent.vuln_ports import port_document


def _tcp_spans(port_range: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for token in port_range.split(","):
        if not token.startswith("T:"):
            continue
        body = token[2:]
        if "-" in body:
            left, right = body.split("-", 1)
            spans.append((int(left), int(right)))
        else:
            spans.append((int(body), int(body)))
    return spans


def test_service_parallelism_is_the_per_ip_check_concurrency(monkeypatch):
    # V1.9.3: no 3-4 clamp (a leftover from the old port-slice lanes).
    monkeypatch.setenv("SCAN_SERVICE_PARALLELISM", "8")
    assert service_parallelism() == 8
    monkeypatch.setenv("SCAN_SERVICE_PARALLELISM", "2")
    assert service_parallelism() == 2
    monkeypatch.setenv("SCAN_SERVICE_PARALLELISM", "1")
    assert service_parallelism() == 1
    monkeypatch.setenv("SCAN_SERVICE_PARALLELISM", "500")
    assert service_parallelism() == 32
    monkeypatch.setenv("SCAN_SERVICE_PARALLELISM", "junk")
    assert service_parallelism() == 6  # V1.10.3 port semaphore

def test_full_tcp_range_splits_into_four_lanes_that_cover_every_port():
    lanes = lanes_for_port_range("T:1-65535", lanes=4)
    assert len(lanes) == 4
    spans = [span for lane in lanes for span in _tcp_spans(lane["port_range"])]
    spans.sort()
    assert spans[0][0] == 1
    assert spans[-1][1] == 65535
    for (_lo, hi), (next_lo, _next_hi) in zip(spans, spans[1:]):
        assert next_lo == hi + 1
    owners = [lane for lane in lanes if any(lo <= 22 <= hi for lo, hi in _tcp_spans(lane["port_range"]))]
    assert len(owners) == 1
    names_on_22 = []
    for item in port_document()["tcp"]:
        spec = str(item.get("ports") or "")
        hit = False
        for part in spec.split(","):
            piece = part.strip()
            if not piece:
                continue
            if "-" in piece:
                left, right = piece.split("-", 1)
                hit = int(left) <= 22 <= int(right)
            else:
                hit = piece.isdigit() and int(piece) == 22
            if hit:
                break
        if hit:
            names_on_22.append(str(item.get("service")))
    assert names_on_22
    assert all(name in owners[0]["services"] for name in names_on_22)


def test_udp_token_is_not_copied_onto_every_lane():
    lanes = lanes_for_port_range("T:1-65535,U:53", lanes=4)
    udp = [lane["port_range"] for lane in lanes if "U:53" in lane["port_range"]]
    assert len(udp) == 1


def test_merge_keeps_a_live_lane_when_another_lane_saw_no_ports():
    merged = merge_service_lane_polls([
        {
            "status": "completed",
            "progress": 100,
            "vulnerabilities": [],
            "evidence": {"host_coverage": {"10.0.0.8": {"verdict": "degraded_no_ports", "open_tcp_ports": []}}},
        },
        {
            "status": "completed",
            "progress": 100,
            "vulnerabilities": [{"name": "ssh"}],
            "evidence": {
                "host_coverage": {
                    "10.0.0.8": {
                        "verdict": "observed_unverified",
                        "open_tcp_ports": [22],
                        "open_udp_ports": [],
                    }
                },
                "report_result_count": 1,
            },
        },
    ])
    assert merged["status"] == "completed"
    assert merged["progress"] == 100
    coverage = merged["evidence"]["host_coverage"]["10.0.0.8"]
    assert coverage["verdict"] == "observed_unverified"
    assert coverage["open_tcp_ports"] == [22]
    assert len(merged["vulnerabilities"]) == 1


def test_merge_keeps_the_reason_when_no_lane_saw_a_service():
    merged = merge_service_lane_polls([
        {
            "status": "completed",
            "progress": 100,
            "vulnerabilities": [],
            "evidence": {
                "host_coverage": {
                    "10.0.0.8": {
                        "verdict": "degraded_no_ports",
                        "reason": "service catalog probed; no listener answered",
                        "open_tcp_ports": [],
                        "nvts_launched": 3,
                    }
                }
            },
        },
        {
            "status": "completed",
            "progress": 100,
            "vulnerabilities": [],
            "evidence": {
                "host_coverage": {
                    "10.0.0.8": {
                        "verdict": "full",
                        "reason": "0 TCP / 0 UDP port(s), 3 NVT(s) ran",
                        "open_tcp_ports": [],
                        "nvts_launched": 3,
                    }
                }
            },
        },
    ])
    coverage = merged["evidence"]["host_coverage"]["10.0.0.8"]
    assert coverage["verdict"] == "degraded_no_ports"
    assert coverage["reason"] == "service catalog probed; no listener answered"
    assert coverage["open_tcp_ports"] == []


def test_merge_stays_running_until_every_lane_finishes():
    merged = merge_service_lane_polls([
        {"status": "completed", "progress": 100, "vulnerabilities": [], "evidence": {}},
        {"status": "running", "progress": 40, "vulnerabilities": [], "evidence": {}},
    ])
    assert merged["status"] == "running"
    assert merged["progress"] == 70
