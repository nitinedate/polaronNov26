# V65 - Active process hand-off / In Process UI

## Problem
After Get segments reached 100%, the pipeline could still show a stale `Next: Download` or no active downstream card even though the extraction worker had been queued.

## Changes
- Added authoritative backend hand-off helper `mark_pipeline_agent_running`.
- `_queue_disk_build` now marks `virtual_disk_agent` running immediately before the Celery build task is dispatched.
- Prior Drive mount / Download / List folder / Get segments cards are closed as done at this hand-off.
- Frontend `currentAgentDisplay` now prefers a real `running` orchestration card over stale `current_agent_label` metadata.
- Running cards now include a visible `IN PROCESS` badge.
- Applies to disk and mobile jobs that use the shared build/extraction hand-off.

## Expected UI
`Get segments 100% -> Virtual disk IN PROCESS -> Extraction IN PROCESS -> Register artifacts ...`

## Validation
Focused backend regression tests: 4/4 passed.
