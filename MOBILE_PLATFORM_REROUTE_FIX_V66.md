# V66 — Mobile platform authoritative reroute fix

## Problem
An iPhone export could be registered through a backend whose current service identity was `mobile-android`. The registered package path clearly identified Apple/iPhone evidence, but stale Android ownership fields remained in `jobs.disk_source`. The Android build worker then received the task and correctly refused it with:

`Extraction refused— mobile-android received conflicting Android/iOS evidence metadata`

## Fix
1. Registered `evidence_files` are now considered during platform reconciliation, before extraction is queued.
2. Strong evidence/manifest platform detection is authoritative over stale UI/service metadata.
3. `persist_owner_on_disk_source()` overwrites stale `axiom_platform` and `evidence_platform` when a platform is verified; it no longer retains a contradictory prior value.
4. `_queue_disk_build()` reconciles mobile platform ownership before dispatch.
5. Mobile extraction is explicitly dispatched to `ios-build` or `android-build` with `apply_async(queue=...)`; it no longer relies on the producer API's default Celery route.
6. If a stale task still lands on the wrong platform worker, `MobileExtractionHandoff` automatically republishes it to the correct platform queue and preserves the job in `processing` state.

## Expected flow for this case
`APPLEIPHON...zip/.pas/.ufd/.ufdx` -> platform verified as iOS -> job type becomes `ios_mobile` -> owner becomes `iosagent` -> task dispatched to `ios-build` -> iOS virtual disk/package processing begins.

## Validation
`backend/tests/test_mobile_platform_reroute_v66.py`: 4/4 passed.

The broader legacy mobile test collection cannot fully run in this build container because optional runtime dependencies (`psycopg2`) and an unrelated stale `ACTION_AGENTS` import are missing; these are collection/environment issues, not V66 assertion failures.
