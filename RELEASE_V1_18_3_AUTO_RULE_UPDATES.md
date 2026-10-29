# Polaron V1.18.3: YARA rules update themselves, like the indicator feeds

Nothing on Threat intelligence needs a file to be found and browsed any more.

| Section | How it stays current |
|---|---|
| Indicator feeds | Subscribed sources update at 11:30 and 15:30 (since 1.18.0). The file import is folded under "Add another source by hand" and is only needed without internet access. |
| YARA rule packs | **New:** Recommended sources -> "YARA rules for Android app code": subscribe to YARA Forge core, extended or full (one at a time), or to any rule URL (.yar, .yara or .zip). They update at the same times. New rules are compiled first; if they do not compile, the previous rules stay in use and the error is shown on the pack. Every update is audited. |
| Suppressions | Nothing to download: examiners' false-positive decisions, applied automatically to every new scan. |
| Search indicators | Looks up the indicators loaded now; it grows with every update. |

"Subscribe to all" now also subscribes YARA Forge core when no rule package is subscribed.

## Fixed
- A .zip rule pack could not contain a rule file larger than 16 MiB, so YARA Forge extended (16.8 MiB) and full
  (20 MiB) were refused although the pack limit is 32 MiB.

## Install
Overlay the patch and run `script_docker\start_docker_local.cmd` (migration 054). Then Threat intelligence ->
Recommended sources -> YARA rules -> Subscribe on "YARA Forge core".
