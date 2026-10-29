# Docker OS detection fix v79

v78 compared combined stdout and stderr with linux, so Docker warnings could falsely trigger the Windows-container error. v79 reads only a marked OSType line, prints the detected OS, rejects an explicit windows value, and reports unreadable responses separately. It does not change Docker contexts or container mode.

Apply over v78, preserving .env, settings, and certificates, then run your usual launcher.

In PowerShell, verify the selected engine:

```powershell
docker info --format '{{.OSType}}'
docker context show
```

If it reports linux, no container-mode change is needed. If it reports windows, use Docker Desktop tray menu > Switch to Linux containers, wait for the engine, and retry.

Validation: parsing cases cover clean Linux output, warnings before/after, CRLF, Windows output, missing markers, and conflicting markers. Archive CRC and unchanged-file byte comparison passed. These are parsing checks; live Windows PowerShell and Docker Desktop were unavailable.
