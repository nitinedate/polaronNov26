"""No clean report may be inferred from completed edge tasks alone."""
from app.services.scanner_agent_jobs import evaluate_edge_ingest_verdict


def test_completed_edge_task_without_service_evidence_is_not_clean():
    result = evaluate_edge_ingest_verdict(
        target_list=['192.0.2.10'], skipped_details=[], skipped_set=set(),
        assessed_list=['192.0.2.10'], status='completed', partial=False,
        partial_reason=None, error=None, external_scan_id='task-1', report_id='report-1',
        task_status='Done', hosts_attempted=1, hosts_assessed=1, report_result_count=3,
        plugin_error_count=0, scan_start='2026-10-13T00:00:00Z',
        scan_end='2026-10-13T00:01:00Z', assessment_complete=True,
        assessment_verdict='assessed', report_read_error=None, vulnerability_count=3,
        evidence_present=True,
    )
    assert result['verified_complete'] is True  # engine execution can finish
    assert result['clean_eligible'] is False  # no family check-pass evidence


def test_missing_target_stays_incomplete():
    result = evaluate_edge_ingest_verdict(
        target_list=['192.0.2.10','192.0.2.11'], skipped_details=[], skipped_set=set(),
        assessed_list=['192.0.2.10'], status='completed', partial=False,
        partial_reason=None, error=None, external_scan_id='task-1', report_id='report-1',
        task_status='Done', hosts_attempted=2, hosts_assessed=1, report_result_count=3,
        plugin_error_count=0, scan_start='2026-10-13T00:00:00Z',
        scan_end='2026-10-13T00:01:00Z', assessment_complete=True,
        assessment_verdict='assessed', report_read_error=None, vulnerability_count=3,
        evidence_present=True,
    )
    assert result['verified_complete'] is False
    assert result['missing_ip_targets'] == ['192.0.2.11']


def test_central_port_only_observation_does_not_fake_pass():
    from app.services.scanner_service_policy import analyze_services
    data = analyze_services([], host='192.0.2.10', coverage={'open_tcp_ports': [445]})
    assert data['coverage_complete'] is False
    smb = next(x for x in data['services'] if x['service_id'] == 'SVC-01')
    assert smb['port_hint_count'] == 1
    assert smb['status'] == 'not-tested'
