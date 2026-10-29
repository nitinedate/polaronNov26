# Get Segments long request patch

## Modified
- frontend/src/lib/api.ts: timeoutMs=0 does not schedule AbortController cancellation. All ordinary calls retain their bounded timeouts.
- frontend/src/lib/forensicApi.ts: evidence/ingest-path uses timeoutMs=0 instead of 300 seconds.
- frontend/src/components/forensic/HostEvidencePanel.tsx: 502/504 recovery checks persisted job state before reporting failure.

## Important architectural limitation
This is a tactical fix. Proxies/load balancers outside the bundle, connection resets, browser navigation, crashed workers, or upstream timeouts can still terminate HTTP requests. For size-independent operation, register_segments must run as an idempotent background job with persisted status, bounded I/O operations and client polling. Do not turn all proxy timeouts off without worker supervision. If the server continues registration after HTTP disconnect, verify committed segments and case state before retrying to avoid duplicate work.

## Production rollout
Back up the application; rebuild frontend; verify effective nginx -T and any upstream load balancer timeout; test deliberate 504 / disconnect and long fake registration; ensure existing evidence is not written or reset.
