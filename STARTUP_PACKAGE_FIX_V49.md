# Polaron V49 - Complete Windows Startup Package

## Fixed packaging defect

The previous package contained launchers that invoked `script_docker/start_docker.ps1`,
and the startup manifest listed that file as mandatory, but the file itself was absent.
Windows PowerShell therefore failed before Docker initialization with exit code `-196608`.

V49 restores the missing PowerShell startup orchestrator and adds explicit launcher checks.
The launchers use `%~dp0`, so the project can be extracted to any drive/folder; no `H:` path
is hard-coded.

## Startup behavior

- First launch creates missing root `.env` and `script_docker/start_docker.settings.json`.
- `-PrepareOnly` creates/validates first-launch configuration without Docker.
- `-ValidateOnly` validates Docker Compose configuration and bind paths without starting containers.
- Ordinary launches rebuild/compile application images while retaining Docker dependency cache.
- `-RefreshDependencies` (or legacy `-NoCache`) performs an explicit dependency refresh.
- Public profiles validate/issue trusted certificates and start the HTTPS gateway on TCP 80/443
  before product stacks.
- Nitin profile serves the configured public IP and domain; production profile uses the public IP only.
- Existing evidence, `.env`, settings, volumes, and unrelated Docker projects are not intentionally pruned.

## Launch

From the project root on Windows:

```powershell
.\script_docker\start_docker_nitin.cmd
```

Validation only:

```powershell
.\script_docker\start_docker_nitin.cmd -ValidateOnly
```

Preparation only:

```powershell
.\script_docker\start_docker_nitin.cmd -PrepareOnly
```

Public TCP 80 and 443 must be forwarded by the router to the Windows host. For the domain profile,
DNS A must resolve to the configured public IPv4 address.
