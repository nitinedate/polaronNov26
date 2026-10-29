# V55 Gateway API Routing Fix

## Symptom
The UI and HTTPS gateway load, and the forensic `api` container is healthy, but access-token sign-in returns HTTP 502 Bad Gateway.

## Root cause
Product APIs are intentionally published on Windows loopback only (`127.0.0.1:8081/8082/8083/8084`). The nginx gateway runs in a different Docker container and was proxying to `host.docker.internal:<port>`. A host-loopback-only published port is not a reliable cross-container route on Docker Desktop, so nginx could not reach an otherwise healthy API.

## V55 fix
- Gateway joins external network `aetheris-common`.
- Forensic API gets alias `forensic-api`.
- Android API gets alias `android-api`.
- iOS API gets alias `ios-api`.
- Vulnerability API gets alias `vuln-api`.
- nginx routes directly to `<alias>:8080`.
- 8081/8082/8083/8084 remain bound to `127.0.0.1`, preserving LAN isolation.
- Startup creates `aetheris-common` before the public gateway on a first launch.
- Frontend performs a short product-aware readiness poll for transient 502/504 responses before retrying login.

## Validation
`pytest -q backend/tests/test_gateway_nginx.py` => 5 passed.
Compose YAML structures were parsed for forensic, Android, iOS, vulnerability, and gateway definitions.
