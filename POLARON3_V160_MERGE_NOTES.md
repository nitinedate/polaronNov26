# Polaron3 selective vulnerability-scanner V1.6.0 integration

This package starts from the uploaded `polaron3.zip`. Only relevant scanner,
React scan-details, and central agent-version integration was applied; other
project content and existing production configuration were retained.

## Integrated
- Scanner engine processing/coverage distinction, no false full-service assessment.
- Per-IP scan time limit opt-in (`SCAN_IP_BUDGET_SEC=0` by default).
- State-aware Greenbone GMP stop behavior, improved polling and lane error accounting.
- Agent build label parsing for `1.5.9-v47.2` and `1.5.9+v47.2`.
- React scan-job list/modal amber incomplete-coverage state (engine progress is separate).
- Full per-IP source evidence and selected target preservation.

## Explicitly preserved from uploaded polaron3
- `PORT_PROFILE=full` default, with full 1-65535 TCP scan available, rather
  than overriding a requested full sweep to Nexus-only. The configured
  52-family Nexus catalog and additive service ports remain available.
- Existing capacity-aware/thermal IP worker scheduling (`SCAN_IP_PARALLELISM=auto`).
- Existing one-attempt, short-timeout control plane requests, to avoid WAN slowdown.
- Edge job reclaim/resume logic; no forced cancellation of legitimate full-sweep tasks.
- Existing production Compose/scripts, TLS/static-IP configuration, forensic/mobile code.

## Deploy safely
1. Back up the existing project and wait for active scan results to upload.
2. Merge updated code, KEEP your private `.env`, certificate files, evidence,
   PostgreSQL and Greenbone Docker data volumes. No volume deletion.
3. On the laptop, explicitly set `SCAN_IP_BUDGET_SEC=0`; set
   `MAX_SCAN_RUNTIME_SEC=0` only if your operational policy allows unlimited
   per-job runtime. Review current `PORT_PROFILE` for authorized scope.
4. On the central server, rebuild/restart only affected backend and frontend
   application services. On laptop rebuild scanner-agent only.
5. Confirm scan targets, Greenbone native task reports, scan-config and NVT
   availability, observed services, and rendered coverage before reporting clean.

No deployment to a real Docker daemon or production IP was performed here.
