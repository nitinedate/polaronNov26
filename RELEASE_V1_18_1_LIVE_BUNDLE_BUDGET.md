# Polaron V1.18.1: phones with many apps no longer fail with "triage bundle exceeds 2048 MB"

The collector was allowed to copy up to 4096 MB of app packages, but Malware Detection accepts bundles up to
2048 MB (`MALWARE_LIVE_MAX_BUNDLE_MB`), so a phone with many large apps failed at the very end. Apps were also
copied alphabetically, so a few large store games could use up the space before the apps that matter.

## Fixed
- Malware Detection gives the collector an app-package budget that fits its bundle limit (limit minus 512 MB for
  logs and lists: 1536 MB by default). The collector's own default is 1536 MB too, for older helpers.
- App packages are copied riskiest first: sideloaded apps with accessibility / notification / device-admin access,
  other sideloaded apps, store apps with such access, then other store apps, smaller first within each group.
  Resource-only split APKs (split_config.*.apk) are not copied; they contain no code.
- Apps left out by the budget are listed under the scan's Coverage tab instead of failing the read.
- Bundles stream to and from storage instead of being loaded into memory; the local copy is verified once.
- Host helper v5.55 passes the budget through; deployment (or the HostDrive agent) restarts the helper.

To scan more app packages, raise `MALWARE_LIVE_MAX_BUNDLE_MB` (the budget follows it).
