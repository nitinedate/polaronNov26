# Unified forensic processing UI patch

## Changes
- Disk jobs show the same 13-stage `SerialPipelineBanner` from the start of processing.
- Prior to backend `pipeline_progress.serial_pipeline` availability, a frontend-only adapter converts existing extraction/orchestration telemetry into the same card layout.
- Once authoritative `serial_pipeline` appears, it replaces the adapter without changing layout.
- Extraction status and count in Stage 3 use checkpoint-uploaded files and don't mark extraction done until `extracted_disk_uri` exists.
- Enumerating displays file-discovery counts without a false denominator.
- Mobile jobs retain their current screens.

## Installation
Copy the three files under `frontend/src/components/forensic/` over the corresponding project paths. Then run your normal frontend build and redeploy the frontend image. The backend and existing case data are unchanged.

## Limitations / validation
This is a frontend presentation patch, not a backend extraction/performance or concurrency change. Run `npm ci && npm run build` within frontend using the project's actual lockfile and dependencies, then verify a new disk job through inventory, uploading, manifest finalization, and serial processing. The provided archive does not contain node_modules, so a full TypeScript/Vite build has not been completed here.
