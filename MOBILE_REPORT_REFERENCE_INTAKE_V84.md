# Mobile forensic report layout and intake-guided examination — V84

Based on the supplied nine-page mobile forensic report example. The new mobile-only section order is: Cover, TOC, Introduction, Tools Used, Device Information, Extraction Summary, Objective/Observation with Findings, Annexure. Disk reports retain their original order.

## Intake-guided investigation

The mobile objective and procedure are adapted from `background`, `incident_summary`, and `custom_objectives` instead of the hard-coded cattle-feed example. The report asks about offer letters, appointments, applications, messages/chats, document/image/video/audio evidence, transfers/deletion, and unavailable sources. A new bounded source-ledger queries only `rag_chunks` for the current `job_id`, with source file paths and extracted snippets for examiner verification.

The existing LLM polishing path remains available for narrative observations. The source-ledger is deterministic and is appended outside model prose. Search hits are unverified candidate leads, NOT proof of misconduct. Zero hits never establish absence. No assumptions about acquiring private app data, successful decryption, unauthorized device use or employee behavior are made.

## Reference-document data cautions

The supplied PDF has inconsistencies (mobile scope alongside laptop language; iOS reference alongside Android procedures; different organization names). Its page **layout** and chapter labels are reused, not its unverified assertions, example findings, subject, or tool names. Actual acquisition facts and branding still come from case data/existing configured report exporter.

## Limitations and testing

Tests: `cd backend && PYTHONPATH=. pytest -q tests/test_mobile_report_format_v84.py`. Full report regeneration, HTML/PDF/DOCX pagination, and a live vector/RAG/LLM evaluation were not executed here. Evidence-oriented queries should be profiled against your real corpus and indexed in PostgreSQL appropriately. A multi-tenant case must never be queried without job isolation and its existing database schema search path.
