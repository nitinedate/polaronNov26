# Polaron V63 - Get segments authoritative manifest progress fix

## Problem reproduced
The mobile export folder can contain a byte-bearing ZIP plus small `.pas`, `.ufd`, and `.ufdx` companion files. The folder-list stage reported all four as segment-like, while case-layout registration selected only the payload ZIP. The orchestration ledger was also initialized at a fixed 10% and registration did not publish per-file progress or a terminal 100% state. The UI therefore remained on **Get segments 10%** after the evidence register log already said registration was complete.

## V63 behavior
1. Case-layout mobile runs now register the complete forensic package manifest: payload ZIP/shards plus `.pas`, `.ufd`, `.ufdx`, and distinct metadata ZIP companions.
2. Expensive extraction still uses only byte-bearing payload ZIP/shards. Companion registration does not make the extractor walk the sealed mobile tree.
3. `Get segments` progress is driven from one authoritative registration manifest. The card records `completed`, `total`, `skipped`, current filename, and a real percentage.
4. Existing/reused evidence rows count as processed, so resume/retry cannot pin the card.
5. Explicit unreadable/retry items are counted and surfaced as skipped/review items instead of silently freezing progress.
6. When the segment readiness manifest is valid, the stage is marked `done / 100%` and orchestration advances to `virtual_disk`.
7. Snapshot healing now recognizes a committed ready `segment_readiness` plus evidence rows as terminal completion for Get segments, preventing a later poll from reverting it to 10/50%.

## Validation
Focused V63 tests: **13/13 passed**.

The tests cover case-layout mobile exports with sharded payloads, the four-file `.zip/.pas/.ufd/.ufdx` layout, payload-only extraction selection, and Get-segments progress moving from a ratio to 100% completion.
