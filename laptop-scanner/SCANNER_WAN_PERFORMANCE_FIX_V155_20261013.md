# Scanner WAN / performance fix V1.5.5 (2026-10-13)

## Why the scanner stalled

The agent's CentralApi `_request` instantiated a new `httpx.Client` for **every** request. `CENTRAL_API_TIMEOUT_SEC=0` disabled read deadlines; each PATCH could use up to 5 exponential-backoff retries (connect timeout up to 20s) directly on the Greenbone poll loop. The dispatcher also flushed log batches synchronously. An intermittent public HTTPS link therefore affected local polling and result progress even when OSPd itself was healthy.

## Changes

- Reuse a single thread-safe HTTPX client with keep-alive connections and bounded connection/read timeouts.
- Progress PATCH / heartbeat / job-next / log POST use one fast attempt; the next polling interval reattempts as appropriate.
- Preserve reliable final-results uploads with a longer timeout, retries and the existing outer upload-retry loop. Uploads are **not** discarded on a transient outage, but container restarts can still interrupt non-persisted uploads.
- Rate-limit repetitive progress snapshots to 45 seconds (terminal updates are immediate), and log one concise warning per minute rather than a traceback on every failed PATCH.
- Move routine log POST off the dispatcher loop using a bounded, single-flight daemon thread.
- Preserve Nexus-style full configured TCP scans and service evidence; this fix **does not** shorten the scanning range or claim all service families were tested.
- Add diagnostics in `Test-Scanner-Link-And-Load.ps1`.

## Configurable settings in `.env`

```
CENTRAL_API_TIMEOUT_SEC=15
CENTRAL_API_CONNECT_TIMEOUT_SEC=4
CENTRAL_RESULT_TIMEOUT_SEC=120
PROGRESS_REPORT_INTERVAL_SEC=45
```

Defaults are also in `docker-compose.yml`, so pre-existing `.env` files without new keys are supported. `CENTRAL_API_TIMEOUT_SEC=0` now means **use 15 seconds**, not wait forever.

## Address mismatch

The agent logs show `https://122.179.140.167` while an earlier central production setup was configured for `https://122.179.141.248`. The patch **does not change either address automatically**: validate which is the correct live endpoint, its TLS certificate, port forwarding, firewall and API responsiveness. Changing to the wrong control plane can strand jobs.

## Deployment on Windows laptop

Back up the deployed scanner folder, retain the existing `.env`, `scanner-agent/runtime`, `logs` and Docker volumes. Replace source files with this update, then in PowerShell:

```
cd C:\Users\Public\laptop-scanner
.\Test-Scanner-Link-And-Load.ps1
docker compose build scanner-agent
docker compose up -d --no-deps scanner-agent
```

**CAUTION**: Recreating `scanner-agent` while a scan is active interrupts the agent's in-memory tracking. Wait for the running job to upload its final results or plan a controlled resume; do not execute that restart on a live job.

## Investigate real engine throughput

Compare `docker stats --no-stream` plus OpenVAS/OSPd/GVMD logs before and after. Full 1-65535 TCP scans and prioritized UDP scans are intrinsically more expensive than narrowed common-port scans. This patch reduces communication overhead, but cannot guarantee IP/hour rates; engine performance still depends on live services, network latency, NVT inventory, laptop CPU/RAM and enabled policies. Do not mark untested services clean.

## Validation

- Scanner tests: 117 passed including new timeout and outage tests.
- Python compilation and ZIP integrity checks pass.
- No live Windows/Docker/cloud-WAN tests were available in this environment.
