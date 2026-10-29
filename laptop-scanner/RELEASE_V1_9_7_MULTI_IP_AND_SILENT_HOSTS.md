# Laptop Scanner V1.9.7 — multi-IP jobs: silent hosts, parallel visibility, "incomplete" not "failed"

Agent build `1.9.7-v57.0` (cumulative: V1.9.1–V1.9.6). Central change in
`polaron-v1.9.7-update.zip` (backend + the laptop-scanner copy it ships).

## What job de53e2fe showed (Advanced template, 2 IPs, agent 1.9.6)

**The two IPs ran in parallel.** OpenVAS task for 192.168.0.195 started 14:20:29, for
192.168.0.163 at 14:20:30. Each IP has its own 60-minute clock, and both were stopped by
it at 15:20:41 and 15:20:42 — impossible if one had waited for the other. OSPd itself
does not queue scans: `max_scans`, `max_queued_scans` and `min_free_mem_scan_queue`
default to 0 (= no limit) in ospd-openvas, and the compose file does not set them.

**Why 192.168.0.195 stayed at 0%.** OpenVAS reports a host's progress as 0% until its
port scan has finished. Advanced scans all 65,535 TCP ports (plus 27 priority UDP). The
agent's pre-probe of 154 common ports on .195 got no answer at all — no open port, no
TCP reset — so the host is off or drops everything, and every port has to time out.
That port scan did not finish in the hour. 192.168.0.163 answered through the Docker
loopback, finished its port scan in about 8 minutes, had 18 open services, and was at 78%
at the limit (50 results; 3 checks timed out: Directory Scanner 1200 s, UPnP Detection
600 s, Apache Struts Detection 320 s).

**Why the job said "failed".** The central server requires every requested IP to have
host results in the OpenVAS report. .195 had none, so the whole job was red "failed"
although .163 had 50 results. With 40 IPs per job, one offline IP would fail every job.

## Changes

**Agent — silent hosts are stopped early (`SCAN_SILENT_HOST_SEC`, default 900).**
If the pre-probe got no answer on any port *and* OpenVAS is still at 0% after 15 minutes,
the agent stops that IP's task and reports it as "No response — not assessed": "none of
the 154 TCP ports the agent probed answered (no open port, no reset), and OpenVAS found
no open port in 15 min of port scanning. The host is offline or drops all traffic." Its
slot goes to the next IP instead of being held for the full hour. A host that refused
even one port (a reset means it is up) is never treated as silent; a host whose progress
moves past 0% is left alone; the scanner laptop itself is excluded; `0` turns it off.

**Agent — the Activity column says what a 0% IP is doing.**
"Waiting for a free scan slot (4 IPs scan at once)", "Port scan running (25 min) – OpenVAS
shows 0% until the port scan has finished", "In progress (37%, 10 min)", "No response: …".

**Agent — a parallel-status line every 5 minutes**, e.g.
`Job … parallel status: 2 IP(s) scanning now [192.168.0.10 37% 12m, 192.168.0.195 port scan 12m] | 0 starting | 0 waiting for a free slot (up to 4 at once) | 0 finished of 2`.

**Central — "incomplete" instead of "failed" when the agent accounts for the gap.**
When every IP without results was stopped by the agent's own limits (per-IP time limit
before port scanning finished, or "no response") and at least one other IP was assessed,
the job is amber "incomplete": findings kept, never verified or clean-eligible, and the
reason names the IPs ("no response, not assessed (host offline or all traffic dropped):
192.168.0.195" or "stopped at the per-IP time limit before port scanning finished: …").
Unchanged: an IP that simply never appears in the report, with no agent explanation,
still fails the job; so do result-count mismatches and jobs where no IP was assessed.

## Scanning 40 IPs

The agent scans `SCAN_IP_WORKERS_FIXED` IPs at once (default 4, range 1–32); the rest wait
and start as slots free up. Each IP's time limit starts when its own OpenVAS task starts,
so waiting costs nothing. Each OpenVAS host scan uses roughly a CPU core and up to about
1 GB while its checks run, so 40 at once on one laptop would slow every host and run into
the per-IP limits. A realistic setting is 4 on a 4-core/8 GB laptop and 6–8 on 8 cores/16 GB.

For bulk scans use **Nexpose · Full audit** (or Safe network audit / Nessus Basic Network
Scan): the main service ports, typically a few minutes per host. Advanced/Exhaustive scan
all 65,535 ports — 10–60+ minutes per host, the longest on hosts that drop traffic.

## Upgrade

Laptop (no scan running): extract `laptop-scanner-v1.9.7-update.zip` over the install, then
run `Apply-Scanner-v1.9.7.cmd` (checks the files, stops if OpenVAS is scanning, backs up and
cleans `.env`, re-runs configure-openvas, recreates scanner-agent — which also adds the
feed mount that is still missing on the laptop — and verifies).

Central: extract `polaron-v1.9.7-update.zip` over the central install and restart the
backend service that ingests agent results (the vuln `api` service).

## Verify

- Agent log: `AGENT BUILD 1.9.7-v57.0`; on multi-IP jobs a `parallel status` line every 5 min.
- An offline IP in a job: `no response - none of N probed TCP ports answered …` after
  about 15 minutes, then the next IP starts.
- Central: a job with one offline IP and other IPs assessed shows amber "incomplete"
  with the IP named, not red "failed".

## Testing

Agent: 420 tests pass (9 new: silent-host detection only when nothing answered; stopped
as "no response" and its slot freed well before the per-IP limit; a host that reset a
port is not silent; rule can be turned off; a host that starts progressing is left
alone; Activity texts; parallel-status line, repeated 25 times for thread timing).
`Apply-Scanner-v1.9.7.ps1` re-run against the stub `docker.exe` scenarios. Central: 9 new
verdict tests plus the 11 existing verdict tests pass. In the wider central test set the
same 8 tests fail with and without this change (checked by running them with the change
removed): 3 need the `pyotp` module missing in the test sandbox, 5 assert older SQL text
or severity labels.
