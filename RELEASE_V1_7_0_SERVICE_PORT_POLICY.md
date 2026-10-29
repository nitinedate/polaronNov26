# Laptop Scanner / Polaron V1.7.0 — service port policy: check only services that can have Low+ findings

Date: 2026-10-14. Cumulative (includes V1.6.5–V1.6.9). Agent build **1.7.0-v49.0**.

## 1. What the screenshot shows (job 1e610661, 172.20.10.2)
The IP shows 6 Info results, 0 services observed and "51 not tested".
**172.20.10.x is the usual iPhone Personal Hotspot range.** Windows normally treats a hotspot as a *Public*
network, where its firewall drops inbound SMB, RPC and RDP. If 172.20.10.2 was the scanning laptop itself,
as earlier scans were, the result is expected: no service answered.
The scanner could not say so because its TCP probe recorded only "open or not". A port that refused the
connection (host up, nothing listening) and a port that never answered (firewall or offline) were both
just "not open". With no open port, every service fell back to "not tested".

I cannot confirm the exact cause without that job's logs. After this upgrade the IP itself shows it,
for example "No exposed services - 0 policy ports closed, 87 not answering (firewall blocking or host offline)".

## 2. The service port policy
One file, `scanner-agent/agent/service_port_policy.json`, now defines what a scan checks. The server has an
identical copy, and a test keeps the two in sync. It lists **67 services on 87 TCP and 25 UDP ports**.
Each service is a network service that can produce **Low, Medium, High or Critical** findings.
A scan with the default port scope (`PORT_PROFILE=nexus`) checks **exactly** the enabled ports and nothing else.
Policy version: `aetheris-service-ports-1.0`.

| Category | Service | TCP | UDP | Can produce Low+ findings such as |
|---|---|---|---|---|
| Application servers | Java RMI | 1099 | — | remote class loading and deserialization flaws |
| Application servers | GlassFish admin | 4848 | — | default credentials, admin console CVEs |
| Application servers | Oracle WebLogic | 7001, 7002 | — | deserialization and console CVEs |
| Application servers | Apache JServ (AJP) | 8009 | — | Ghostcat file read/inclusion |
| Application servers | JBoss / WildFly | 9990 | — | management console exposure, deserialization CVEs |
| Containers | Docker API | 2375, 2376 | — | unauthenticated Docker API leading to host takeover |
| Containers | Docker registry (5000) | 5000 | — | unauthenticated image pull and push |
| Containers | Kubernetes API | 6443 | — | anonymous access, API server CVEs |
| Containers | kubelet | 10250 | — | anonymous kubelet API leading to container exec |
| Databases | Microsoft SQL Server | 1433 | 1434 | outdated versions, weak authentication, browser service exposure |
| Databases | Oracle Database / TNS | 1521 | — | TNS listener CVEs, default accounts |
| Databases | MySQL / MariaDB | 3306 | — | outdated versions, weak or empty passwords |
| Databases | PostgreSQL | 5432 | — | outdated versions, weak authentication |
| Databases | CouchDB | 5984 | — | admin party / unauthenticated access, CouchDB CVEs |
| Databases | Redis | 6379 | — | unauthenticated access leading to code execution |
| Databases | Elasticsearch | 9200, 9300 | — | unauthenticated access to indices, Elasticsearch CVEs |
| Databases | Memcached | 11211 | 11211 | unauthenticated access, UDP amplification |
| Databases | MongoDB | 27017 | — | unauthenticated databases, outdated versions |
| Directory | Kerberos | 88 | 88 | weak encryption types, pre-authentication issues, KDC CVEs |
| Directory | LDAP / LDAPS / Global Catalog | 389, 636, 3268, 3269 | 389 | anonymous bind, cleartext binds, weak TLS, CLDAP amplification |
| File transfer | FTP / FTPS | 21, 990 | — | anonymous or cleartext login, outdated server with known CVEs, weak TLS on FTPS |
| File transfer | Apple Filing Protocol | 548 | — | guest access, outdated AFP servers |
| File transfer | rsync | 873 | — | unauthenticated modules exposing files |
| File transfer | NFS | 2049 | 2049 | world-readable exports, NFS CVEs |
| File transfer | TFTP | — | 69 | unauthenticated file read/write |
| Mail | SMTP / SMTPS / submission | 25, 465, 587 | — | open relay, cleartext auth, weak TLS, outdated mail servers with known CVEs |
| Mail | POP3 / POP3S | 110, 995 | — | cleartext auth, weak TLS, outdated servers |
| Mail | IMAP / IMAPS | 143, 993 | — | cleartext auth, weak TLS, outdated servers |
| Messaging | MQTT | 1883 | — | unauthenticated brokers exposing messages |
| Messaging | Apache ZooKeeper | 2181 | — | unauthenticated access to cluster data |
| Messaging | RabbitMQ / AMQP | 5672, 15672 | — | default credentials, management API exposure |
| Messaging | Apache Kafka | 9092 | — | unauthenticated brokers |
| Network infrastructure | DNS | 53 | 53 | open recursion, zone transfer, cache poisoning and version CVEs |
| Network infrastructure | RADIUS | — | 1812, 1813 | weak shared secrets, RADIUS protocol CVEs |
| Network infrastructure | Cisco Smart Install | 4786 | — | unauthenticated configuration download/replace |
| Network infrastructure | NTP | — | 123 | monlist/mode 6 amplification, NTP CVEs |
| Network infrastructure | SNMP | — | 161, 162 | default community strings, information disclosure |
| Network infrastructure | Syslog | — | 514 | unauthenticated log injection, syslog daemon CVEs |
| Network infrastructure | RIP routing | — | 520 | route injection with RIPv1 |
| Network infrastructure | IPMI / BMC | — | 623 | IPMI 2.0 hash disclosure, cipher zero |
| Network infrastructure | SSDP / UPnP | — | 1900 | UPnP CVEs and amplification |
| Network infrastructure | mDNS | — | 5353 | information disclosure and amplification |
| Printers | IPP printing | 631 | — | CUPS and printer firmware CVEs, unauthenticated administration |
| Printers | JetDirect raw printing | 9100 | — | unauthenticated printer access (checks avoid sending print data) |
| RPC | rpcbind / portmapper | 111 | 111 | RPC service exposure, amplification, rpcbind CVEs |
| Remote access | SSH / SFTP | 22 | — | weak key exchange/ciphers/MACs, outdated OpenSSH or Dropbear with known CVEs, default accounts |
| Remote access | Telnet | 23 | — | cleartext logins, default credentials, outdated daemons |
| Remote access | rexec / rlogin / rsh | 512, 513, 514 | — | trust-based logins without passwords, cleartext credentials |
| Remote access | Android Debug Bridge | 5555 | — | unauthenticated shell on devices |
| Remote access | VNC | 5900-5909 | — | no or weak authentication, outdated servers |
| VPN | IPsec / IKE / L2TP | — | 500, 1701, 4500 | aggressive mode PSK exposure, weak transforms, IKE CVEs |
| VPN | PPTP VPN | 1723 | — | MS-CHAPv2 weaknesses, deprecated protocol |
| Virtualisation | VMware ESXi / vCenter | 902 | 902 | ESXi and vCenter CVEs, exposed management |
| VoIP | SIP / VoIP | — | 5060 | unauthenticated registration, SIP stack CVEs |
| Web | HTTP web servers | 80, 81, 8000, 8080 | — | outdated servers and frameworks, missing security controls, exposed admin pages, injection flaws |
| Web | HTTPS / TLS web servers | 443, 4443, 8443, 9443, 10443 | — | weak protocols and ciphers, certificate problems, outdated servers and frameworks |
| Web | Web application (3000) | 3000 | — | exposed development servers and dashboards |
| Web | Kibana | 5601 | — | exposed dashboards, Kibana CVEs |
| Web | Web admin (9000) | 9000 | — | exposed admin consoles |
| Web | Prometheus / metrics (9090) | 9090 | — | unauthenticated metrics and admin APIs |
| Web | Git / GitLab | 9418 | — | unauthenticated repository access, GitLab CVEs |
| Web | Webmin | 10000 | — | Webmin CVEs including remote code execution |
| Windows | Microsoft RPC / WMI endpoint mapper | 135 | — | exposed DCE/RPC endpoints, RPC CVEs |
| Windows | NetBIOS name service | — | 137 | name service information leakage and spoofing |
| Windows | SMB / CIFS | 139, 445 | — | SMBv1 enabled, signing not required, MS17-010 and other SMB CVEs, null sessions |
| Windows | Remote Desktop | 3389 | 3389 | NLA disabled, weak TLS, BlueKeep-class CVEs |
| Windows | WinRM | 5985, 5986 | — | HTTP (unencrypted) WinRM, weak authentication |

### Ports removed from the old Nexus list

| Port | Service | Why it is not checked |
|---|---|---|
| 20/tcp | ftp-data | FTP data channel, not a listening service; FTP findings are reported on 21/tcp |
| 67-68/udp | dhcp | network-scoped protocol; it cannot be checked against one IP address |
| 138/udp | netbios-dgm | datagram service with no separate checks; NetBIOS issues are reported on 137/udp and SMB ports |
| 4789/udp | vxlan | overlay transport with no OpenVAS vulnerability checks |
| 5004/udp | rtp | media stream ports with no OpenVAS vulnerability checks |

## 3. What changed in scanning and results
- **Scope:** the `nexus` port range is now exactly the policy. The fast-port list, the catalog padding and
  the Compose default `UDP_PORT_RANGE` no longer add ports. Extra ports can still be added on purpose with
  `SERVICE_EXTRA_TCP_PORTS` / `SERVICE_EXTRA_UDP_PORTS` or a policy's additional ports.
- **Per-policy choice:** in **Scan policies → New policy → Services to check**, every policy service is
  listed with its ports and example issues. Untick a service to stop scanning its ports. This is saved as
  `disabled_services` and validated against the policy.
- **Probe:** the agent's TCP probe now covers every policy TCP port and keeps three outcomes:
  - open;
  - closed: the connection was refused, so the host is up and nothing listens;
  - no answer: a firewall dropped the probe, or the host is offline.
  Greenbone's own port scan still runs, and a port it finds open always counts as open.
- **Verdict:** if Greenbone's port scan finished without errors and the probe also found nothing open, the IP
  is **"No exposed services"**, a finished result with the counts. It is not "Incomplete" and not
  "not tested". If the probe saw an open port that Greenbone missed, the old mismatch warning still applies.
  A Greenbone port-scanner error still marks the IP incomplete.
- **Service states:** a service whose TCP ports were all probed and none open is **Closed** or **No answer**,
  never "not tested". "Not tested" now only means "open, but no check result".
- **Policy services table:** in Scan details, each host lists every policy service with:
  - its state: Low+ finding, Open with no Low+ finding, Closed, No answer, or Not observed;
  - each port's state;
  - its Low/Medium/High/Critical counts.
  Informational rows never count as findings.
- **Findings chart:** shows **Low and above** by default. "Show N informational" brings the Info rows back.
  They are kept as evidence for ports and OS.

## 4. Upgrade
No new `.env` values are needed. `PORT_DISCOVERY_RANGE` and `UDP_PORT_RANGE` are ignored for `nexus`.
- **Laptop:** extract over the folder, keeping `.env`, `.lan-fingerprint`, `scanner-agent\runtime\` and `logs\`.
  Then run `docker compose build scanner-agent` and `docker compose up -d --no-deps scanner-agent`.
- **Central:** copy the overlay files and rebuild the backend and frontend images. No database migration is needed.
- **To check a run:** the `port_discovery` event now carries `open_ports`, `closed_port_count` and `filtered_port_count`:
  ```powershell
  docker compose logs --tail 2000 scanner-agent | Select-String 'port_discovery|no_exposed_services|No exposed'
  ```
- **To scan a Windows laptop for real exposure,** run it on a Private/Domain network profile, or scan it from
  another machine. On a Public profile the firewall blocks almost everything, and "No exposed services" is the
  correct answer.

## 5. Testing
- Laptop agent: **296 passed** (10 new). The new tests cover:
  - the policy contents and its exact difference from the old scope;
  - ignoring the Compose UDP default;
  - switching services off and adding extras;
  - the three-way probe;
  - both no-exposed-services verdicts, and that the verdict does not change without evidence or with scanner errors;
  - the screenshot case, with 0 "not tested" and SMB shown as "TCP 139, 445 did not answer";
  - the policy table with a Medium on 445, where Info rows are not counted;
  - the job loop end to end.
- Central focused suite: 82 passed. The same 4 failures are pre-existing in the original package.
- Frontend: no type errors in the changed files; `vite build --mode vuln` succeeds.
- **Not tested live:** how Docker Desktop reports refused versus dropped connections to LAN hosts. If it turns
  refusals into timeouts, closed ports will show as "No answer". The verdict stays "No exposed services" either way.
