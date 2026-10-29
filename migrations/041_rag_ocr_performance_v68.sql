-- V68 RAG/OCR performance indexes
CREATE INDEX IF NOT EXISTS ix_job_artifacts_rag_unchunked ON job_artifacts(job_id,id) WHERE coalesce(metadata->>'serial_chunked','false')<>'true';
CREATE INDEX IF NOT EXISTS ix_ocr_results_artifact_page_created ON ocr_results(job_artifact_id,page_index,created_at DESC);
CREATE INDEX IF NOT EXISTS ix_rag_chunks_job_path_type_idx ON rag_chunks(job_id,file_path,chunk_type,id);
