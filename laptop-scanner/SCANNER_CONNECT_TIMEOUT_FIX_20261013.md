# Desktop scanner central API timeout recovery

## Change
`scanner-agent/agent/main.py` handles exhausted retryable central API timeouts and HTTP 502/503/504 responses without printing a dispatcher traceback. Retry waits grow up to 60 seconds and preserve active local OpenVAS jobs. A recovery message is emitted when polling succeeds.

This is a client-side availability safeguard, **not** a fix for an unreachable central server, gateway, or router. Confirm which public IP is authoritative before changing `CENTRAL_API_URL`.

## Windows deployment
1. Back up the currently installed laptop-scanner folder. Stop any active scan only after assessing its work-state and persistence.
2. Extract the ZIP to any folder or drive, retaining your existing `.env` and local credentials.
3. From the extracted laptop-scanner folder run:
   `docker compose build --no-cache scanner-agent`
   `docker compose up -d --no-deps --force-recreate scanner-agent`
   `docker compose logs --tail 100 -f scanner-agent`
4. Confirm heartbeat and jobs/next return HTTP 200 once the central server is reachable.

## Network diagnosis
From the desktop: `Test-NetConnection 122.179.140.167 -Port 443`
From the central host: `docker logs --since 30m aetheris-gateway-gateway-1` and `docker logs --since 30m aetheris-vuln-api-1`.
Do not disable TLS validation or expose agent tokens. Persistent TCP connect timeouts require checking routing/firewall/NAT and server load.

## Verification
Python compilation and tests/test_agent_instance_v149.py (3 tests) passed. Not validated against the user's live Docker network.
