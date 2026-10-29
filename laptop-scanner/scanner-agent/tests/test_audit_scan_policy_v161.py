from agent.audit_scan_policy import audit


def test_full_tcp_priority_udp_covers_all_configured_service_hints(monkeypatch):
    for key in ('UDP_PORT_RANGE', 'SCAN_TCP_CUSTOM_PORTS', 'SCAN_UDP_CUSTOM_PORTS'):
        monkeypatch.delenv(key, raising=False)
    result = audit('full', 'priority')
    assert result['requested_tcp_ports'] == 65535
    assert result['service_families'] == 52
    assert result['families_with_port_hints_in_scope'] == 52
    assert result['port_policy_eligible'] is True
    assert result['actual_greenbone_execution_verified'] is False


def test_udp_off_is_not_mistaken_for_full_service_transport_coverage(monkeypatch):
    for key in ('UDP_PORT_RANGE', 'SCAN_UDP_CUSTOM_PORTS'):
        monkeypatch.delenv(key, raising=False)
    result = audit('full', 'off')
    assert result['requested_udp_ports'] == 0
    assert result['port_policy_eligible'] is False
    assert result['missing_hint_families']
