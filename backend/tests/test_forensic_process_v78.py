"""Completion, isolation, traceback and grounded question regressions."""
import json
from types import SimpleNamespace
import pytest
from app.services import forensic_serial_pipeline as pipeline
from app.services import forensic_serial_stages as stages
from app.services import process_completion as completion
from app.services import forensic_failure_alerts as alerts
from app.services.forensic_investigation_questions import QUESTIONS, questions_for_title
from app.services.forensic_question_analysis import validate_candidates, render_question_analysis, analyze_questions
from app.services.mobile_forensic.models import NormalizedArtifact


def stage_rows(active='chunk', status='running', **counts):
    result=[]
    seen=False
    for i,(name,_,_) in enumerate(pipeline.STAGES):
        if name==active:
            seen=True
        row={'id':str(i),'stage':name,'status':status if name==active else 'pending' if seen else 'done'}
        if name==active:
            row.update(counts)
        result.append(row)
    return result

def test_inventory_card_uses_the_filesystem_walk_percent():
    rows = stage_rows(active="inventory", status="running", total_items=0, completed_items=0)
    next(row for row in rows if row["stage"] == "inventory")["operation"] = "Extension census from registered files — 257,583 files"
    snap = pipeline.snapshot_from_rows(
        rows,
        {"phase": "inventory", "inventory_ui_pct": 3, "total": 0, "completed": 0},
    )
    card = next(stage for stage in snap["stages"] if stage["id"] == "inventory")
    assert card["pct"] == 3
    assert card["process_status"] == "in process"
    assert "257,583" in card["operation"]


@pytest.mark.parametrize('state,label',[('running','writing in'),('failed','failed'),('queued','next'),('waiting','writing in'),('done','completed')])
def test_process_status_mapping(state, label):
    snap=pipeline.snapshot_from_rows(stage_rows(status=state,total_items=10,completed_items=10))
    card=next(x for x in snap['stages'] if x['id']=='chunk')
    assert card['process_status']==label
    if state not in {'done','skipped'}:
        assert card['pct']<100 and not snap['complete']


def test_parse_item_count_cannot_exceed_extracted_files():
    snap = pipeline.snapshot_from_rows(stage_rows(
        active="parse", status="running", total_items=46731,
        completed_items=9718, skipped_items=40853, failed_items=0,
    ))
    card = next(stage for stage in snap["stages"] if stage["id"] == "parse")
    assert card["completed"] + card["failed"] + card["skipped"] == 46731
    assert card["total"] == 46731


def test_cpu_processing_and_later_wait_labels():
    snap=pipeline.snapshot_from_rows(stage_rows(active='parse', total_items=10,completed_items=2))
    cards={s['id']:s for s in snap['stages']}
    assert cards['parse']['process_status']=='in process'
    assert cards['chunk']['process_status']=='wait'


def test_ocr_sidecar_bucket_empty_is_not_sealed():
    rows=stage_rows(active='recovery')
    next(x for x in rows if x['stage']=='ocr')['details']={'parallel_complete':True,'parallel_completed':10,'parallel_total':10}
    card=next(x for x in pipeline.snapshot_from_rows(rows)['stages'] if x['id']=='ocr')
    assert card['pct']<100 and card['status']!='done'

@pytest.mark.parametrize('done,total',[(9,10),(11,10)])
def test_counter_mismatch_cannot_seal(done,total):
    with pytest.raises(pipeline.StageWaiting):
        stages.validate_stage_barrier(object(),'job','recovery',{'total':total,'completed':done},stage_run_id='stage')


def test_stale_sidecar_reaper_releases_only_expired_claims():
    import inspect
    from app.services.safe_parallel import reap_stale_sidecars

    source = inspect.getsource(reap_stale_sidecars)
    assert "status IN ('queued','running')" in source
    assert "heartbeat_at" in source
    assert "status='pending'" in source
    assert "reap_stale_sidecars" in inspect.getsource(completion.assert_no_active_producers)


def test_sidecars_block_completion(monkeypatch):
    monkeypatch.setattr(completion,'fetchone',lambda db,sql,params=None:{'t':'sidecars'} if 'to_regclass' in sql else {'c':1})
    with pytest.raises(pipeline.StageWaiting,match='independent producers'):
        completion.assert_no_active_producers(object(),'job')


def test_zero_work_and_no_sidecars_allows_barrier(monkeypatch):
    monkeypatch.setattr(completion,'fetchone',lambda db,sql,params=None:{'t':None} if 'to_regclass' in sql else {'c':0})
    completion.assert_no_active_producers(object(),'job')


def test_report_does_not_use_ready_status_as_proof(monkeypatch):
    monkeypatch.setattr(pipeline,'stage_rows',lambda *a:stage_rows(active='validation'))
    with pytest.raises(pipeline.StageWaiting,match='sealed'):
        completion.assert_report_ready(object(),'job')


def test_artifact_identity_is_job_scoped():
    params=dict(artifact_type='app_message',source_path='/data/msgstore.db',source_row_id='1')
    assert NormalizedArtifact.make_stable_id(job_id='A',**params)!=NormalizedArtifact.make_stable_id(job_id='B',**params)
    assert NormalizedArtifact.make_stable_id(job_id='A',**params)==NormalizedArtifact.make_stable_id(job_id='A',**params)


def test_questions_cover_requested_areas():
    assert len(QUESTIONS)==22
    ids={q['id'] for q in questions_for_title('Mobile Chat & Messaging Applications')}
    assert {'offer','chat_conduct','document_transfer','company_images'}<=ids
    assert not questions_for_title('Unrelated invented topic')


def test_llm_cannot_invent_quotes_or_fields():
    sources={'offer:1':{'question_id':'offer','content':'Offer from ABC for Engineer on 2026-01-01.','file_path':'Downloads/offer.pdf','chunk_id':'abc'}}
    raw=[{'source_id':'offer:1','quote':sources['offer:1']['content'],'fields':{'employer':'ABC','role':'CEO','joining_date':'2027-01-01'}},
         {'source_id':'offer:1','quote':'Accepted employment at XYZ.'}, {'source_id':'other','quote':sources['offer:1']['content']}]
    valid=validate_candidates(raw,sources)
    assert len(valid)==1 and valid[0]['fields']=={'employer':'ABC'}
    assert valid[0]['status']=='candidate — examiner review required'


def test_render_escapes_evidence_markup():
    analysis={'questions':[{'id':'q','question':'A|B?','status':'candidate'}],
        'findings':[{'question_id':'q','quote':'<script>bad</script>|x','file_path':'a','chunk_id':'1','fields':{}}]}
    rendered=render_question_analysis(analysis)
    assert '<script>' not in rendered and '&#124;' in rendered


def test_full_remote_traceback_is_preserved(monkeypatch):
    writes=[]
    monkeypatch.setattr(alerts,'ensure_alert_schema',lambda db:None)
    monkeypatch.setattr(alerts,'execute',lambda db,sql,params=None:writes.append(params))
    exc=RuntimeError('parent error')
    exc.remote_traceback='Traceback (most recent call last):\noriginal_parser.py:17\n'+('trace\n'*2000)
    alerts.record_failure(object(),'job','parse','task',exc)
    assert writes[0]['trace']==exc.remote_traceback
    assert writes[0]['recipient']=='ndate1976@gmail.com'
    alerts.record_failure(object(),'job','parse','task',exc)
    assert writes[1]['key']==writes[0]['key']


def test_failed_smtp_keeps_outbox_pending(monkeypatch):
    from app.services.email_service import EmailService
    writes=[]
    monkeypatch.setattr(alerts,'ensure_alert_schema',lambda db:None)
    monkeypatch.setattr(alerts,'fetchone',lambda *a,**k:{'id':1,'stage':'parse','job_id':'job','recipient':'test@example.invalid','attempt':'1','traceback':'full trace','delivery_attempts':1})
    monkeypatch.setattr(alerts,'execute',lambda db,sql,params=None:writes.append((sql,params)))
    monkeypatch.setattr(EmailService,'send',lambda *a,**k:False)
    assert alerts.deliver_alerts(SimpleNamespace(commit=lambda:None))=={'sent':0}
    assert "status='pending'" in writes[0][0]


def test_retrieval_is_scoped_and_foreign_hits_are_rejected(monkeypatch):
    from app.retrieval import hybrid
    calls=[]
    def fake(db,jid,query,**kw):
        calls.append((jid,kw['schema_name']))
        return [{'job_id':'other-job','content':'Offer from XYZ for Engineer','file_path':'other','id':'1'}]
    monkeypatch.setattr(hybrid,'hybrid_retrieve',fake)
    result=analyze_questions(object(),'job','Mobile Email & Attachments',schema_name='firm_a')
    assert calls and all(c==('job','firm_a') for c in calls)
    assert all(not q['source_ids'] for q in result['questions']) and not result['findings']


def test_report_local_cache_reuses_each_query_without_cross_case_sharing(monkeypatch):
    from app.retrieval import hybrid
    calls=[]
    monkeypatch.setattr(hybrid,'hybrid_retrieve',lambda *a,**k:calls.append(a[1]) or [])
    cache={}
    analyze_questions(object(),'job','Mobile Email & Attachments',schema_name='firm_a',retrieval_cache=cache)
    n=len(calls)
    analyze_questions(object(),'job','Mobile Email & Attachments',schema_name='firm_a',retrieval_cache=cache)
    assert len(calls)==n
    analyze_questions(object(),'other','Mobile Email & Attachments',schema_name='firm_a',retrieval_cache=cache)
    assert len(calls)==2*n


def test_graph_expansion_requires_case_and_never_walks_shared_taxonomy():
    from app.services.neo4j_sync import graph_expand
    captured={}
    class Session:
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def run(self,sql,**params):captured.update(sql=sql,params=params);return []
    driver=SimpleNamespace(session=Session)
    assert graph_expand(driver,['catalog-id'])==[]
    assert not captured
    graph_expand(driver,['catalog-id'],job_id='job-a')
    assert captured['params']['jid']=='job-a' and 'all(n IN nodes(path)' in captured['sql']


def test_inventory_does_not_seal_deferred_company_analysis():
    with pytest.raises(pipeline.StageWaiting, match='Company information analysis'):
        stages.validate_stage_barrier(object(), 'job', 'inventory',
            {'total':10,'completed':10,'done':True,'company_leakage':{'status':'deferred'}},stage_run_id='stage')


def test_completed_snapshot_requires_all_stages_and_validation():
    rows=stage_rows(active='validation',status='done')
    assert pipeline.snapshot_from_rows(rows)['complete']
    rows[-1]['status']='waiting'
    assert not pipeline.snapshot_from_rows(rows)['complete']


@pytest.mark.parametrize('acquired',[True,False])
def test_quality_producers_serialize_without_writing_on_conflict(monkeypatch,acquired):
    from contextlib import contextmanager
    from app.services import mobile_quality_ocr as quality
    calls=[]
    @contextmanager
    def lock(db,schema,key):
        assert schema=='firm_a' and key=='quality:job'
        yield acquired
    monkeypatch.setattr(pipeline,'pipeline_execution_lock',lock)
    monkeypatch.setattr(quality,'_route_forensic_quality_to_ocr_impl',lambda *a,**k:calls.append('write') or {'checked':1})
    db=SimpleNamespace(info={'firm_schema':'firm_a'})
    if acquired:
        assert quality.route_forensic_quality_to_ocr(db,'job')=={'checked':1}
        assert calls==['write']
    else:
        with pytest.raises(pipeline.StageWaiting,match='still writing in'):
            quality.route_forensic_quality_to_ocr(db,'job')
        assert not calls
