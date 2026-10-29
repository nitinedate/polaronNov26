# High-risk service port additions and finding severity

Added high-value TCP probes for Docker API (2375/2376), etcd (2379/2380), Kubernetes control and kubelet (10250/10255/10257/10259), Vault (8200), Consul (8500/8501), WebLogic (7001/7002), AMQP/RabbitMQ (5672/15672), Kafka (9092/9093), EPMD (4369), MQTT (1883/8883), ICS (502/4840), Jenkins (50000), monitoring/admin services and others. Priority UDP includes CoAP (5683) and BACnet (47808). Existing entries have been retained.

The catalog `priority` field is discovery/scheduling priority, NOT actual vulnerability severity. A port being open is not proof of a vulnerability. Only evidence-backed vulnerability tests should receive severity.

## Existing severity ranges (unchanged)

- **CVSS v3/v4:** Critical 9.0-10.0; High 7.0-8.9; Medium 4.0-6.9; Low 0.1-3.9; Informational 0.0 / no score.
- **CVSS v2 compatibility:** Critical 10.0; High 7.0-9.9; Medium 4.0-6.9; Low 0.1-3.9; Informational 0.0 / no score.
- Existing `VULN_SEVERITY_BASIS` remains the source-basis selector; the code prefers source CVSS signals.

## Coverage

`PORT_PROFILE=full` already requests all 65,535 TCP ports, so adding catalog entries chiefly improves `vuln`/selective service discovery, descriptions and priority analysis; it does not increase full TCP range. `UDP_PROFILE=priority` includes targeted UDP ports; `UDP_PROFILE=full` is exhaustive but may take much longer. Ensure the active agent profile is correctly set and that Greenbone NVT inventory and Full and fast config are loaded.

Scan only systems in your authorized assessment scope. These changes do not guarantee detection of vulnerabilities on any specific host.
