"""Pre-chunk already parsed text while GPU OCR is busy."""
from __future__ import annotations
import json
from app.db.sql_helpers import execute,fetchall

_MEDIA_EXTS={".jpg",".jpeg",".png",".gif",".webp",".heic",".mp4",".mov",".avi",".mkv",".webm",".3gp"}


def prechunk_parsed_evidence(db,job_id,*,limit=2000):
    from psycopg2.extras import execute_values
    from app.services.dual_rag_index import _chunk_text
    from app.services.rag_text import extract_text_from_normalized as _extract_text_from_normalized
    from app.services.forensic_serial_policy import CHUNK_SIZE,CHUNK_OVERLAP,CHUNK_POLICY
    media_exts=sorted(_MEDIA_EXTS)
    rows=fetchall(db,"""SELECT ja.id,ja.file_path,ja.extension,ja.encyclopedia_artifact_id,
        (SELECT apr1.normalized FROM artifact_parse_results apr1 WHERE apr1.job_artifact_id=ja.id ORDER BY apr1.created_at DESC LIMIT 1) AS normalized,
        (SELECT string_agg(o2.ocr_text, E'\n' ORDER BY o2.page_index) FROM (SELECT DISTINCT ON (o1.page_index) o1.page_index, o1.ocr_text FROM ocr_results o1 WHERE o1.job_artifact_id=ja.id ORDER BY o1.page_index, o1.created_at DESC) o2) AS ocr_text
        FROM job_artifacts ja WHERE ja.job_id=:jid
          AND coalesce(ja.metadata->>'serial_chunked','false')<>'true'
          AND lower(CASE WHEN left(coalesce(ja.extension,''),1)='.' THEN ja.extension ELSE '.'||coalesce(ja.extension,'') END) <> ALL(:media_exts)
          AND coalesce(ja.metadata->>'ocr_quality_checked','true')='true'
          AND coalesce(ja.ocr_status,'') NOT IN ('pending','processing','queued','running')
          AND EXISTS(SELECT 1 FROM artifact_parse_results apr WHERE apr.job_artifact_id=ja.id)
        ORDER BY ja.id LIMIT :lim""",{'jid':job_id,'lim':max(100,min(int(limit),10000)),'media_exts':media_exts})
    values=[];ids=[]
    for row in rows:
        text=_extract_text_from_normalized(row.get('normalized'))
        # Avoid indexing the same OCR/native text twice. Native parser output is
        # preferred; OCR only contributes text that is materially different.
        ocr=str(row.get('ocr_text') or '')
        b=' '.join(str(text or '').split())
        o=' '.join(str(ocr or '').split())
        if o and b:
            if o in b or b in o:
                o=''
        combined='\n'.join(x for x in (b,o) if x)
        chunks=_chunk_text(combined,CHUNK_SIZE,CHUNK_OVERLAP) if combined.strip() else []
        seen_chunks=set()
        chunks=[c for c in chunks if not (c in seen_chunks or seen_chunks.add(c))]
        if not chunks: continue
        aid=str(row['id']);ids.append(aid)
        for idx,content in enumerate(chunks): values.append((job_id,row['file_path'],idx,content,row.get('encyclopedia_artifact_id'),json.dumps({'job_artifact_id':aid,'serial_pipeline':True,'chunk_policy':CHUNK_POLICY,'pre_ocr_parallel':True})))
    if values:
        paths=list({v[1] for v in values})
        execute(db,"DELETE FROM rag_chunks WHERE job_id=:jid AND file_path=ANY(:paths) AND chunk_type='evidence'",{'jid':job_id,'paths':paths})
        with db.connection().connection.cursor() as cur:
            execute_values(cur,"""INSERT INTO rag_chunks(job_id,file_path,chunk_index,content,artifact_id,chunk_type,metadata)
              VALUES %s""",values,template="(%s,%s,%s,%s,%s,'evidence',%s::jsonb)",page_size=1000)
        execute(db,"""UPDATE job_artifacts SET metadata=coalesce(metadata,'{}'::jsonb)||jsonb_build_object('serial_chunked',true,'serial_chunk_policy',CAST(:p AS text),'serial_chunk_status','text','pre_ocr_parallel',true)
          WHERE id=ANY(CAST(:ids AS uuid[]))""",{'ids':ids,'p':CHUNK_POLICY})
    db.commit();return {'status':'ok','rows_considered':len(rows),'artifacts_chunked':len(ids),'chunks':len(values)}
