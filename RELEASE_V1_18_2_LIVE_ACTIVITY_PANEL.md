# Polaron V1.18.2: see every command, from reading the phone to the verdict

## Activity panel (Scan a connected phone)
The page now stays with the run from start to end and shows:
1. **On the phone** - every command, as it runs: adb shell commands (getprop, pm list packages, dumpsys ..., logcat,
   the root check), each app package copied or skipped by the size budget, or for an iPhone the lockdown, app-list,
   profile and crash-report calls. Each with its status, exit code, output size and duration.
2. **On the Polaron server** - downloading the capture from the workstation, verifying every file against its SHA-256,
   storing it, starting the scan.
3. **Malware scan** - the ten stages with status and timing, then the verdict and "Open results".

The scan results of a live capture have a new **Capture log** tab: the complete, verified record of every command
run on the phone (also kept in the capture's manifest), collector warnings and the server steps.

## Fixed
- A capture whose ingest was interrupted (for example a worker restart) is retried after 15 minutes instead of
  staying at "Scanning what was read..." for ever; a stored capture whose scan was not created gets its scan.
- The server steps and phone log are no longer overwritten when the capture is stored.
