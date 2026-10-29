# Polaron V1.10.3 — scan coverage, 5-IP / 6-port semaphores, forensic stage resume

Agent build **1.10.3-v63.0**. Apply the files in this zip over the project root (same paths).

## 1. "Completed · coverage incomplete" (jobs b6b7f60c, ccf22aa0)
Cause: any Greenbone check with "nmap" in its name counted as a port scanner. "Nmap OS
Identification (NASL wrapper)" only fingerprints the OS; its 90 s timeout marked the host
`degraded_port_scan_failed` although ports 445/8090 were enumerated and SMB/TLS checks ran.
Fix: only real port scanners count (Nmap NASL wrapper, OpenVAS TCP scanner, SYN scan, Ping
Host, Services, Open TCP Ports). OS-identification and nmap service-detection wrappers are
check warnings. A port-scanner error whose ports all match the agent's TCP probe is reconciled
as a finished scan with a warning. The central server applies the same rule to uploads from
1.10.1/1.10.2 agents and when reading stored jobs. Genuine failures (no ports, real scanner
error, no error evidence) still show as incomplete.

## 2. "Completed with warnings" → "Completed"
Job list, Scan details badge/circle (green), per-IP activity and assessment label now read
Completed. Warning counts and notes are kept in the IP rows and the details panel.

## 3. Semaphores
* IP semaphore **5** (`SCAN_IP_SEMAPHORE`, overrides old `SCAN_IP_WORKERS_FIXED=4` in .env).
* Port semaphore **6** per IP (`SCAN_PORT_SEMAPHORE`): agent TCP pre-probe = at most 6 connects
  per IP at once; OpenVAS max_checks = 6 checks per IP at once (was 4).
* A task found stopped/interrupted that the agent did not stop (restart mid-scan, job 7fc54039
  at 94 %) is restarted once instead of failing the IP (`SCAN_INTERRUPTED_RESTARTS=1`).

## 3a. Field finding: the laptop .env ran the turbo profile
Your laptop `.env` sets `SCAN_PERFORMANCE=turbo` and `TURBO_PLUGINS_TIMEOUT=90`.
* Turbo ran 10-40 OpenVAS checks per IP at once (4 per CPU, cap 40). `SCAN_PORT_SEMAPHORE=6` now
  caps every profile (turbo, fast, standard) at 6 checks per IP, as requested. If scans of a
  single IP get slower, raise `SCAN_PORT_SEMAPHORE` (for example 12).
* `TURBO_PLUGINS_TIMEOUT=90` is the 90-second limit that stopped "Nmap OS Identification" and 61
  HTTP checks on 192.168.0.163. It is left unchanged. Raising it (turbo default 180) gives fuller
  HTTP coverage at the cost of scan time.
* The complete laptop package keeps your `.env`, `.lan-fingerprint`, `scanner-agent/runtime/`
  (agent token and instance id) and `logs/`, sets `SCAN_SERVICE_PARALLELISM=6` and adds
  `SCAN_IP_SEMAPHORE=5`, `SCAN_PORT_SEMAPHORE=6`, `SCAN_INTERRUPTED_RESTARTS=1`.
  It contains your agent token: share it only with the laptop it belongs to.

## 4. Forensic "Stage process cancelled by progressAgent"
* Cancelled / exited stage processes are a resumable wait; they no longer use the 3-attempt
  recovery budget. Parse resumes from committed `parse_status` rows.
* A transient DB error on the stage owner's 1-second control poll no longer SIGTERMs the stage.
* While directory 2 (250GB) extracts, the job stays `indexing` and the barrier uses the saved
  manifest, so stages continue on directory 1 (1TB).
* When directory 2 is saved, parse (incl. a cancelled/failed one) and every finished later stage
  reopen, so the new files go through recovery, OCR, inventory, RAG, enrichment, graph, validation.
* Who stopped the stage is now recorded in the stage error shown in the UI:
  the owner names its reason (progressAgent cancel request, examiner stop, or job paused), or the
  error says the SIGTERM came from outside the application (worker container stop/restart, Docker
  Desktop or host shutdown). Code review found no path inside the project that produces the old
  "cancelled by progressAgent" text while the stage owner is alive, so the field case points to an
  external stop of the `worker-parse` container. Note `REMAP_SIGTERM=SIGQUIT` (cold shutdown) and its
  8 GB memory limit shared by 6 Celery slots plus parse-shard sidecars.
* `Diagnose-Stage-Cancel.cmd [JOB_ID]` prints the parse worker's start time, restart count and OOM
  flag, its shutdown/signal log lines and Docker events for 48 h, and the job's stage timeline,
  progressAgent decisions and stop/pause/directory log lines.

## Deploy
1. Backend + workers: copy `backend/` files, restart backend, forensic workers, progress agent.
2. Frontend: rebuild (`frontend/src/pages/vuln/ScanJobsPage.tsx`).
3. Laptop: copy `laptop-scanner/` files, `docker compose up -d --build` the scanner agent.
   Check the agent log: `parallel: up to 5 IP(s) at once, 6 checks at once per IP`, build 1.10.3-v63.0.
4. Stored scan jobs (inside the api container): `python scripts/repair_scanner_coverage_v1103.py` (dry run), then `--apply`.
5. Current forensic job: run `Diagnose-Stage-Cancel.cmd <JOB_ID>` from the project root and keep the output.
6. Stuck forensic job, only if its parse card shows "retry budget exhausted" (run in the firm schema):
   ```sql
   UPDATE pipeline_stage_runs SET status='waiting', task_id=NULL, error=NULL,
          cancel_requested_at=NULL, recovery_dispatches=0, updated_at=NOW()
    WHERE job_id='<JOB_ID>' AND stage='parse' AND status IN ('waiting','failed');
   ```

## Tests
Scanner agent: 452 passed. Frontend: `tsc --noEmit` clean. Backend: new and changed tests pass; 7 tests in the touched files
fail identically on the untouched baseline (they need a live PostgreSQL).
