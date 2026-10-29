# Polaron V1.26.0: hostile-file parsers confined; removal needs a preserved copy

## 1. Parser sandbox for Malware Detection
The engines that parse hostile files with native code now run in a confined helper process instead of inside the
worker: **YARA** (libyara), **androguard** with its XML parser (lxml/libxml2), **LIEF** (Mach-O), and **APKiD** (its own
YARA). Each worker process keeps one helper. The helper starts with an **empty environment** (no database, storage or
Redis credentials), loads its libraries, then locks itself down with a kernel seccomp filter and resource limits
before it touches any sample. A hijacked parser can no longer:
- open network sockets (no reaching Postgres, Redis, MinIO, the Windows host or the internet);
- start programs or new processes;
- create, change, truncate, rename or delete files (files open read-only), so it cannot overwrite the application
  code on the mounted volume;
- debug other processes, mount, change namespaces, load kernel modules, use BPF, io_uring or keyrings;
- use more than `MALWARE_SANDBOX_MEMORY_MB` (3 GB) or `MALWARE_SANDBOX_CPU_SECONDS`.

**Containment.** A file that crashes or hangs a parser ends only that helper: the scan records the file as
"contained in the sandbox", a fresh helper takes over (YARA rules are re-sent automatically) and the scan continues.
Per-file timeouts: `MALWARE_SANDBOX_APK_SECONDS` (300) for app analysis, the YARA timeout plus 30 s for YARA.

**Fail closed.** If confinement cannot be established on a host, YARA and static analysis are skipped with a note on
every scan rather than run unconfined, and the Threat intelligence page shows "Parser sandbox unavailable".
`MALWARE_SANDBOX=off` (all parsers) or `MALWARE_SANDBOX_APKID=off` (APKiD only) run them unconfined; not recommended.

## 2. Removal from the phone needs a preserved copy
"Remediate" now refuses to remove an app unless the scan evidence already holds its APK and hash, because removal
destroys the app on the phone. Each app shows "APK preserved in the evidence" or "Not preserved". Removing an app
that is not preserved needs an explicit "remove without a preserved copy" choice and a written reason; both are
recorded in the audit log with the consent record. Enforced on the server (HTTP 409), not only in the page.

## Verification
- `backend/tests/test_malware_sandbox_v1_26.py` (12 tests) against real processes: the helper cannot open a socket,
  write a file (including inside the application code), start a program or fork; it can read; it holds no
  credentials; a segfault, a hang and an 8 GB allocation are contained and the next file is served by a fresh helper;
  test probes are refused in production; APKiD-style programs launched under the filter cannot use the network or
  write. The YARA engine finds a match through the helper with the same evidence (rule, metadata, offsets), skips
  only a file whose parser crashed, and skips YARA with a note when confinement is impossible. Malformed APK and
  Mach-O files fail safely. The filter never blocks harmless calls on x86_64 or aarch64.
- Removal: preserved app proceeds; unpreserved app refused (409); override needs a reason (422) and is audited.
- Existing tests: the remediation UI test fixture now marks its apps as preserved (the scenario it describes);
  everything else unchanged. Full backend suite compared test by test with V1.20.1.

## Not verified here
- Inside the real Docker images. Docker's default seccomp profile normally allows a process to add its own filter;
  check the Threat intelligence page shows "Parser sandbox active" after deployment.
- APKiD under confinement (not installed in this sandbox). If it needs to write temporary files, scans will note
  "apkid failed"; then set `MALWARE_SANDBOX_APKID=off` and report it.
- androguard on real APK samples (only malformed input was available here).

## Still open
Live triage on the examiner PC pulls APKs into a temporary folder before bundling (see V1.25.0 notes).
