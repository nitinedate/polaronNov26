import pytest
from app.services import source_coverage as coverage


def test_completed_processing_does_not_claim_full_coverage():
    result = coverage.build_source_coverage(processing_complete=True)
    assert result['processing_complete'] and not result['coverage_complete']
    assert result['status'] == 'unknown'
    assert '100%' in coverage.render_source_coverage(result)


@pytest.mark.parametrize('state', ['key_required', 'partial'])
def test_missing_key_stays_visible_after_100_percent(state):
    result = coverage.build_source_coverage({'whatsapp_evidence_gate': {
        'state': state, 'authorized_key_candidates': 0, 'decryption': {'blocked_files': 2},
        'key_candidates': 'secret-key'}}, processing_complete=True)
    assert result['status'] == 'incomplete'
    assert result['limitations'][0]['code'] == 'missing_key'
    assert 'secret-key' not in str(result)


def test_successful_reprocess_clears_key_limitation():
    result = coverage.build_source_coverage({'whatsapp_evidence_gate': {
        'state': 'ready', 'decryption': {'blocked_files': 0}}}, processing_complete=True)
    assert not result['limitations'] and result['status'] == 'unknown'


@pytest.mark.parametrize('code', ['private_app_data', 'overwritten', 'inaccessible'])
def test_explicit_limitation_visible_and_resolvable(code):
    ds = {'source_limitations': [{'code': code, 'source': 'Mail'}]}
    result = coverage.build_source_coverage(ds)
    assert result['limitations'][0]['code'] == code
    assert result['limitations'][0]['action'] in coverage.render_source_coverage(result)
    ds['source_limitations'][0]['resolved'] = True
    assert not coverage.build_source_coverage(ds)['limitations']


def test_zero_records_does_not_prove_overwriting():
    result = coverage.build_source_coverage(coverage_rows=[{
        'coverage_key': 'priority_whatsapp', 'status': 'acquisition_gap', 'artifacts': 0}])
    assert [x['code'] for x in result['limitations']] == ['acquisition_gap']
    assert 'Absence on the device is not established' in coverage.render_source_coverage(result)


def test_failed_skipped_unsupported_sources_remain_visible():
    result = coverage.build_source_coverage(coverage_rows=[{
        'coverage_key': 'documents', 'status': 'complete_with_exceptions',
        'errors': 1, 'details': {'unsupported': 3}}],
        validation={'ocr_disabled': True, 'extraction_skipped': 2,
                    'exceptions': {'parse_failed': 1}})
    assert {'unsupported', 'processing_exception'} == {x['code'] for x in result['limitations']}
    assert any(x['source'] == 'OCR disabled' for x in result['limitations'])


def test_reads_are_job_scoped_without_schema_mutation(monkeypatch):
    calls = []
    monkeypatch.setattr(coverage, 'fetchone', lambda *a: {'name': 'mobile_coverage'})
    def fetch(db, sql, args):
        calls.append((sql, args))
        return []
    monkeypatch.setattr(coverage, 'fetchall', fetch)
    coverage.collect_source_coverage(None, 'job-1', row={'disk_source': {}})
    assert calls[0][1] == {'jid': 'job-1'}
    assert 'WHERE job_id=:jid' in calls[0][0]


def test_report_pages_omit_the_coverage_block():
    result = coverage.build_source_coverage(processing_complete=True)
    rendered = coverage.render_source_coverage(result)
    report = "Analysis finding.\n\n" + rendered + "\n### Next heading\nKept.\n"
    cleaned = coverage.strip_source_coverage_from_report(report)
    assert "Source limitations" not in cleaned
    assert "100%" not in cleaned
    assert "| Source |" not in cleaned
    assert "### Next heading" in cleaned
    assert "Kept." in cleaned


def test_report_escapes_source_names():
    result = coverage.build_source_coverage({'source_limitations': [
        {'code': 'inaccessible', 'source': '<script>|bad\nsource'}]})
    rendered = coverage.render_source_coverage(result)
    assert '<script>' not in rendered and '&#124;' in rendered


def test_unsupported_inventory_is_finished_processing_with_coverage_exception(monkeypatch):
    from app.services.mobile_forensic import coverage as inventory
    from app.services.mobile_forensic.models import InventoryItem
    rows = []
    monkeypatch.setattr(inventory, 'upsert_coverage', lambda db, jid, key, **kw: rows.append(kw))
    inventory.persist_coverage_snapshot(None, 'job-1',
        [InventoryItem(path='/Download/unknown.xyz', status='unsupported')], {})
    assert rows
    assert all(r['status'] == 'complete_with_exceptions' for r in rows)
    assert all(r['details']['unsupported'] == 1 for r in rows)
    assert all(r['details']['processing_complete'] and not r['details']['coverage_complete'] for r in rows)
