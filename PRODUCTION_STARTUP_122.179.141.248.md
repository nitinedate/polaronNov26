# Production startup: 122.179.141.248

## Updates
- `script_docker/start_docker_prod.cmd` delegates to the existing Windows PowerShell orchestrator.
- Existing orchestrator first validates Docker, Compose and forensic drive mounts, then **stops only six Polaron-owned Compose projects** (gateway, vuln, mobile-ios, mobile-android, forensic, common). Unrelated containers are intentionally not stopped: doing so would interrupt unrelated applications and could cause data loss.
- It builds all managed application stacks, starts the HTTPS gateway, shared infrastructure, forensic, both mobile stacks and vulnerability scanner, then checks health. Docker named volumes and evidence folders are preserved. No `docker system prune`, `down -v` or destructive reset.
- Production gateway frontend now binds `0.0.0.0:3001:80` for HTTP (previously localhost-only). HTTPS binds 80 and 443; the PowerShell startup generates the IP-specific gateway nginx TLS config after certificate issuance.

## Windows PowerShell (run on the Windows Docker host)
```powershell
cd 'C:\path\to\polaron'
.\script_docker\start_docker_prod.cmd -ValidateOnly
.\script_docker\start_docker_prod.cmd
```

For unattended certificate issuance set the `prod.acmeEmail` field in `script_docker/start_docker.settings.json`, or set `CERTBOT_EMAIL`; the project already has `prod.publicIp=122.179.141.248`. The ACME issuance requires an eligible public-IP certificate and reachable HTTP validation at TCP 80; issuance depends on certificate authority support. Existing certificates should not be erased.

## Router / firewall
- On the router forward **WAN TCP 80 -> Windows host TCP 80** and **WAN TCP 443 -> Windows host TCP 443**. Forward TCP 3001 only if direct HTTP access over the public Internet is required (not recommended, as it is unencrypted).
- Reserve the server's *LAN* IP in the router and forward to that LAN IP; do not use the WAN static IP as the destination.
- Allow Windows Defender Firewall inbound TCP 80 and 443 on the correct network profile; allow TCP 3001 only for trusted LAN users if needed.
- The recommended browser entry is `https://122.179.141.248/`, which uses the nginx gateway and keeps the APIs behind it. `http://localhost:3001/` works on the Docker host. For LAN clients use `http://<WINDOWS_LAN_IP>:3001/`.
- If the ISP blocks 80/443, direct HTTPS at this IP will not work without changing upstream forwarding or using an approved reverse proxy/tunnel.

## Verify
```powershell
docker compose --project-directory . --project-name aetheris-gateway -f services/gateway/docker-compose.yml -f deployment/windows-ip-https/docker-compose.gateway-public-https.yml config
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
Test-NetConnection 127.0.0.1 -Port 3001
Test-NetConnection 127.0.0.1 -Port 443
curl.exe -k -I https://127.0.0.1/
```

`-ValidateOnly` does not start or stop containers. The provided archive does not include a certificate or verify real router/firewall connectivity. Run the startup on the actual Windows host to validate the service and public endpoint.
