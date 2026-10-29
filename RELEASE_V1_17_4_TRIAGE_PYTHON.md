# Polaron V1.17.4: Scan a connected phone finds the examiner-kit Python

"No working Python for the examiner kit on this workstation" appeared even though the examiner kit was installed
(tools\host-python). The helper's Python check started Python with Start-Process, waited only 2 seconds and read the
exit code without holding the process handle; in Windows PowerShell 5.1 that exit code can read back empty, so a
working Python was rejected. The same check made device preview and the iPhone name/UDID lookup fall back silently.

## Fixed
- Live triage finds Python itself: examiner kit first, then backend\.venv and .venv. Each is checked by running it
  directly (as the examiner kit does) and confirming it can load the collector, plus pymobiledevice3 for iPhones.
  If none works, the message lists every Python tried and why.
- The helper's shared Python check (Test-PythonExe, Find-KitPython) now keeps the process handle and allows 6 s for
  a cold start, so preview and iPhone name/UDID lookup work too.
- iPhone capture reads model, iOS version and build through pymobiledevice3's get_value() (4.x and 5.x); crash
  reports are copied without a progress bar and still left on the phone. Checked against pymobiledevice3 5.3.2.
- Helper v5.54: the next start_docker run (or the HostDrive agent, within a minute) restarts the helper.

Collector verified on Python 3.9, 3.10, 3.11, 3.12 and 3.13.
