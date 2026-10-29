# Intermittent scanner central API 502 recovery

- Laptop dispatcher treats exhausted retryable network errors as temporary, without aborting active OpenVAS workers or generating repetitive stack traces.
- Gateway upstream connect timeout is 8 seconds (from 30). The existing long read timeout remains for lengthy requests.
- Run `powershell -ExecutionPolicy Bypass -File .\script_docker\Diagnose-Scanner-502.ps1 -PublicUrl https://<YOUR-CENTRAL-IP>` on the **central server**. The script is read-only and checks direct port 8082, gateway logs and container health.
- A 502 still requires correcting a failing upstream; this update does not imply live repair or restore a missing database job.
- Check agent CENTRAL_API_URL: some agent logs target 122.179.140.167 while a deployment gateway file targets 122.179.141.248. Ensure the laptop points to the real current central server with a valid matching TLS certificate.
- Never remove volumes; preserve forensic data and existing task reports.
