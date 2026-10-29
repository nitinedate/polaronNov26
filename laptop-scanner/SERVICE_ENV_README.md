# Aetheris: editable service and CVSS configuration

The `.env` file is the authority for 52 service-family port mappings (SERVICE_<NAME>_TCP/UDP), enabled switches, optional custom ports, and CVSS bands. `.env.example` has the same non-secret settings. After changes, execute `docker compose up -d --build --force-recreate scanner-agent` on the laptop. Verify effective configuration with `docker compose exec -T scanner-agent python -c "from agent.vuln_ports import service_registry,port_document; print(len(service_registry()),len(port_document()['tcp']),len(port_document()['udp']))"`.

Extra custom port examples: `SERVICE_EXTRA_TCP_PORTS=8081,10443`, `SERVICE_EXTRA_UDP_PORTS=1701`; or update an existing SERVICE_<NAME>_TCP/UDP. To add a new **named family**, add a definition in `scanner-agent/agent/service_families.json` and three corresponding `.env` values. A new vulnerability rule/CVE needs a scanner VT/feed, fingerprint predicate, evidence and verification: editing `.env` cannot create an executable detection plugin.

The old `vuln_ports.json` remains a backward-compatible auxiliary port catalog. Its historical `priority` fields are **not** vulnerability scores. CVSS thresholds in `.env` approximate Nessus severity bands; they are not Tenable VPR. Existing central UI severity presentation is outside this laptop-only package and must separately be wired to this policy or to the scanner's actual CVSS score.

`PORT_PROFILE=vuln` uses the configured service port union; `PORT_PROFILE=full` scans TCP 1-65535 and selected UDP. The profile is not a promise of exhaustive CVE coverage. Ensure Greenbone feeds and credentials are available. No live target testing or Nessus parity test is included.
