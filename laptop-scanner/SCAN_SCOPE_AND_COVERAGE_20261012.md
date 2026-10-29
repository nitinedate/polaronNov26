# Scan scope and evidence fidelity

The default scan port profile is now `PORT_PROFILE=full`, `UDP_PROFILE=priority`:
TCP ports 1-65535 with priority UDP ports from the configuration. Set
`UDP_PROFILE=full` only for deliberately exhaustive UDP sweeps; it may be
very slow and high impact. All scans must be limited to authorized targets.

This controls destination ports, **not target IP addresses**. The central
Polaron job supplies the host/IP/CIDR scope to the laptop agent. A finished
GMP task does not mean all 52 service families have been tested. Authenticated
checks need credentials, and network-wide broadcast collectors are separate.

After changing `.env`, recreate the scanner-agent container to load the new
variables and rerun a NEW assessment; completed older reports are immutable.
Wait for `Full and fast`/NVT readiness before accepting OpenVAS jobs.
