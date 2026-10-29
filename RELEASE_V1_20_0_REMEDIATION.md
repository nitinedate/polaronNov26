# Polaron V1.20.0: remove malware from a consenting phone (incident response)

A new Remediation capability: once a scan has flagged malware, an examiner can clean the phone — remove the apps,
then re-scan to confirm. This is for INCIDENT RESPONSE (cleaning a victim's device with consent), kept strictly
separate from the forensic read path, which remains read-only.

## Remediate tab (Android scans)
- Lists the apps flagged malicious or suspicious on the scan — the removal candidates (malicious pre-selected).
- Requires a consent record (who authorised it, when) before anything runs, and a clear red warning that this
  changes the phone and must not be used on a device held as evidence.
- Confirm once for the whole batch. Polaron connects to the phone and, for each app:
  revokes device-admin, disables accessibility (so stalkerware cannot block its own removal), force-stops, then
  uninstalls. With root it also handles system/embedded apps (pm uninstall --user 0, or disable as a last resort).
- Shows what was removed and what is still present (needs root or a factory reset).
- One click to **re-scan the phone** and confirm the malware is gone.

## Safety and separation
- The forensic collector (live_triage) is unchanged and still refuses every state-changing command. Removal is a
  separate module (live_remediate) with its own write path — the read path can never remove apps (there is a test
  that enforces this).
- A new permission, **malware:remediate**, gates removal. It is NOT given to ordinary scan users; an admin assigns
  it. Existing firms gain the permission automatically the first time the malware service runs after this upgrade.
- Every removal is audited (packages, consent, result), and the consent record is stored with the job.
- Helper v5.56 adds the remediation endpoints; the workstation helper must be on this version (start_docker updates it).

## Install
Overlay the patch and run script_docker\start_docker_local.cmd (migration 056). An admin grants malware:remediate to
the examiners who should have it. Then open a completed Android scan -> Remediate.
