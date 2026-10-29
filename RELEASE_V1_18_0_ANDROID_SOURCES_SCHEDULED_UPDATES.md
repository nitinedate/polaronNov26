# Polaron V1.18.0: Android sources and malware definition updates at 11:30 and 15:30

## Android (and iPhone) threat intelligence
Threat intelligence -> Recommended sources now lists 15 vetted sources grouped Android / iPhone / both, each downloaded
and imported by Polaron's own parser:
- **All mobile spyware campaigns (MVT index)**: follows the Mobile Verification Toolkit index (19 campaigns today);
  campaigns MVT adds later are subscribed automatically at the next update.
- Android: Stalkerware (170+ families), Android mercenary campaign (Amnesty 2023), RCS Lab Hermit, WyrmSpy and
  DragonEgg, NoviSpy, ResidentBat, BTMOB, Spyrtacus, Morpheus, EagleMsgSpy, Predator.
- iPhone: Pegasus, Operation Triangulation, Quadream KingSpawn, Predator.
"Subscribe to all" subscribes everything not yet subscribed.

New indicator types close every gap these files had (all 19 now import 11,632 indicators, 0 skipped; 511 were
dropped before): Android signing-certificate SHA-1 (488 stalkerware certificates) and SHA-256 in MVT's form,
Android system properties set by spyware (matched in live getprop and build.prop), iOS configuration-profile ids
(matched in live captures and backups), and server IP addresses that some feeds file as domain names.

## Definition updates at fixed times
- Subscribed feeds and the MVT index update daily at **11:30 and 15:30 (Asia/Kolkata)**:
  `MALWARE_INTEL_SYNC_TIMES=11:30,15:30`, `MALWARE_INTEL_SYNC_TIMEZONE=Asia/Kolkata`.
- An update missed because Polaron was off runs as soon as it is back; each scheduled time runs once.
- Threat intelligence shows the schedule, the next and last update (checked / changed / new / failed) and
  **Update now**. Every update is recorded and audited.
- `MALWARE_INTEL_ONLINE_SYNC` now defaults to `true`; only the feed URLs you subscribe to are fetched. Set it to
  `false` for an air-gapped lab (import files by hand).

## Install
Overlay the patch and run `script_docker\start_docker_local.cmd` (migration 053; `tzdata` added for time zones).
Then Threat intelligence -> Recommended sources -> Subscribe to all, and Scan again on earlier scans.
