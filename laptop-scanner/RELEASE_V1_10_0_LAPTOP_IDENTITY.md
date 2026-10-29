# V1.10.0 — each laptop is recognised by its own name

Agent build `1.10.0-v60.0` (cumulative: V1.9.1–V1.9.9) and the central update
`polaron-v1.10.0-update.zip` (cumulative: central V1.9.7–V1.9.9).

## Why Laptop-DESKTOP-J19GUGP stayed "offline"

The token emailed at sign-in identifies a **user** (tenant + email), not a laptop, so
every laptop of that user binds the same token. Three things then went wrong:

1. **Agent requests** (heartbeat, job claim, progress, results) were matched to a scanner
   record with `... WHERE agent_token_hash = :th LIMIT 1` (`get_edge_agent`). With one
   token on two laptops, both laptops heartbeated and claimed jobs as the same record
   (Laptop-NITIN); the other record (Laptop-DESKTOP-J19GUGP) never received a heartbeat
   and showed offline. Jobs launched on it were never claimed by its laptop.
2. **Binding at sign-in** (`/api/scanners/bind-client-token`) reused the record named in
   `SCANNER_ID` from `.env` — copied with the folder from another laptop — or simply the
   only existing laptop record, so a new laptop could take over another laptop's record.
3. The agent runs in Docker, where the hostname is the container id; the Windows
   computer name never reached the central server.

## What changes

**Laptop**
- `docker-compose.yml` passes the Windows `COMPUTERNAME` to the agent
  (`HOST_COMPUTERNAME`); `AGENT_COMPUTER_NAME` in `.env` is the fallback.
- Every central request carries `X-Aetheris-Agent-Computer` (and
  `X-Aetheris-Agent-Name` when `SCANNER_NAME` is set) next to the existing
  `X-Aetheris-Agent-Instance` (per-install id).
- `Start-Laptop` (token sync) sends the computer name and instance id when binding the
  emailed token, writes `AGENT_COMPUTER_NAME` to `.env`, and creates a new instance id
  when the folder was copied from another PC (`scanner-agent\runtime\agent-instance-computer`
  records which PC the id belongs to).
- `Apply-Scanner-v1.10.0.cmd` sets `AGENT_COMPUTER_NAME` to this PC's name (adds it, or
  corrects a value copied from another laptop).

**Central**
- Two new columns on `vuln_scanners`: `agent_computer_name`, `agent_instance_id` (added
  automatically, `ADD COLUMN IF NOT EXISTS`).
- Agent requests: among the records holding the token, the laptop's own record is chosen
  by computer name (then its own name "Laptop-<computer>" or `SCANNER_NAME`, then
  instance id) and linked to that computer on first contact. A record bound to another
  computer, or named after another laptop, is never used. A laptop of the same user with
  no record yet is **registered automatically as "Laptop-<computer name>"** (or reuses an
  unlinked record with that name). Agents older than V1.10.0 (no computer name) keep the
  previous behaviour, made deterministic (most recently seen record).
- Binding at sign-in uses the same rules, so a copied `SCANNER_ID` no longer takes over
  another laptop's record.
- The scanner list returns `agent_computer_name`; Launch scan shows it after the scanner
  name when the name does not already contain it, e.g. `Nitin-test (DESKTOP-JA5BG0K)`.

## Rollout

1. Central: extract `polaron-v1.10.0-update.zip`, restart `api`, rebuild the frontend.
   Laptops still on older agents keep working as before.
2. Each laptop (no scan running): extract `laptop-scanner-v1.10.0-update.zip`, run
   `Apply-Scanner-v1.10.0.cmd`. Within a minute the laptop's own scanner record shows
   online with its computer name; a laptop without a record appears as
   "Laptop-<computer name>". Running `Start-Laptop.cmd` (sign-in with the emailed
   token) also works and additionally refreshes a copied instance id.

If a laptop folder was copied from another PC, also delete the `SCANNER_ID` and
`SCANNER_NAME` lines from its `.env` (they belong to the other laptop); they are no longer
able to take over the other laptop's record, but they would set the wrong display name.

## Testing

Agent: 430 tests pass (5 new: computer-name precedence, header-safe names, identity on
every request, bind body + heartbeat headers, CLI arguments). `Get-AgentInstanceId`
(new id, kept id, copied folder, older install) and the `.env` update (add, correct,
unchanged) run under PowerShell 7; `Apply-Scanner-v1.10.0.ps1` re-run against the stub
`docker.exe` scenarios (an old compose file without `HOST_COMPUTERNAME` is refused).
Central: 12 new tests (record picker; two laptops with one token resolve to two records;
a new laptop is registered under its own name; an existing record with its name is
reused; unknown tokens still rejected; bind with a copied `SCANNER_ID` binds the laptop's
own record; old bind scripts keep the previous rules — two of these fail without the
fix). Scanner test set: 130 pass; the same 8 unrelated failures as before.
