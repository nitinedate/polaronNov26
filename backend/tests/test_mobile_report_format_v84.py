from app.services.report_renderer import MOBILE_SECTION_ORDER, section_order_for_report_type, section_title
from app.services.report_evidence import gather_mobile_findings_markdown
from app.services.mobile_inquiry_report import build_mobile_inquiry_findings


def test_mobile_order_not_disk():
    assert section_order_for_report_type('mobile_forensic') == MOBILE_SECTION_ORDER
    assert 'os_information' not in MOBILE_SECTION_ORDER
    assert 'artifact_summary' not in MOBILE_SECTION_ORDER
    assert section_title('annexure', mobile=True) == 'ANNEXURE'


def test_intake_questions_and_no_cattle_feed_default():
    text = gather_mobile_findings_markdown({'incident_summary': 'Review employee communications about a new role'})
    assert 'offer letter' in text.lower()
    assert 'Review employee communications' in text
    assert 'cattle feed' not in text


def test_search_scoped_and_qualified(monkeypatch):
    seen = []
    def fake_fetchall(db, sql, params):
        seen.append((sql, params))
        return []
    monkeypatch.setattr('app.services.mobile_inquiry_report.fetchall', fake_fetchall)
    text = build_mobile_inquiry_findings(object(), '11111111-1111-1111-1111-111111111111', {})
    assert len(seen) == 4
    assert all('job_id=CAST(:jid AS uuid)' in sql for sql, _ in seen)
    assert 'does not establish' in text
    assert 'encrypted private-app data' in text.lower()
