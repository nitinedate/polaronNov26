# Polaron V1.22.0: "This computer" evidence now works from home and other sites (no VPN)

V1.21.0 let an examiner keep the image on their own PC while the forensic server processes it, but only on the
office network: the server had to open a connection to the PC, which a home router or another site's firewall
blocks. Now the PC's Client Evidence Agent connects **out** to the Polaron server instead, over the same HTTPS address
the examiner already uses for Polaron. No VPN, no open port on the PC, nothing extra to configure.

## How it works
- When the examiner selects a folder, the browser tells the agent to keep an outbound connection for that share to
  this console (`/api/client-agent/relay`) and which product stack owns the job (disk, Android or iOS).
- The agent holds a few HTTPS long-poll requests open. When the server needs bytes, it queues a request in that
  stack's Redis; a waiting poll hands it to the agent, which reads the bytes from the PC and posts them back.
- The server tries the direct LAN connection first (fastest) and uses the outbound connection automatically when the
  PC cannot be reached. Everything after that is unchanged: read-only mount, tamper detection, processing on the
  server, nothing copied.
- The job card says which way it is connected ("through its outbound connection").

## Security
- The agent authenticates every request with the share's 256-bit token; the server compares it in constant time.
  Each token unlocks exactly one share.
- The agent only connects out to the Polaron console that asked for the share, on the same origin, and only if that
  console is paired (`-ConsoleOrigin`). A request naming any other server is ignored.
- The token is stored on the PC encrypted with Windows DPAPI for the signed-in examiner, so it survives an agent
  restart without being written in plain text.
- Traffic is encrypted by the console's HTTPS certificate. For a self-signed console certificate, install the agent
  with `-TrustServerThumbprint <thumbprint>`; otherwise Windows' normal certificate checks apply.
- The server never connects to the PC in this mode, so there is no inbound port and no address allow-list involved.

## Resilience
- Network drop, laptop sleep or agent restart: the server notices a dropped poll within about a second and puts any
  request it had taken back in the queue. The agent also acknowledges each request as soon as it arrives, so a request
  lost in transit is retried after 15 s (`CLIENT_EVIDENCE_RELAY_ACK_SECONDS`), while a slow upload that was
  acknowledged is given the full time (`CLIENT_EVIDENCE_RELAY_TIMEOUT`, 120 s per 4 MiB block).
- The agent reconnects with back-off up to 30 s and resumes its shares after a restart or reboot.
- Corporate proxies: the agent uses the Windows proxy settings and the signed-in user's proxy credentials.

## Speed
Bytes travel over the PC's **upload**. At 20 Mbit/s a 100 GB image takes at least about 11 hours to read, and
extraction reads parts of an image more than once. Use it for targeted or moderate-size evidence from outside the
office; very large images are faster from a drive attached to the server.

## Install
- **Server:** no new container settings (V1.21.0's are enough). Optional `.env` settings: `CLIENT_EVIDENCE_RELAY_*`
  in `.env.example`. The Polaron console must be reachable from where the examiners work, over HTTPS.
- **Each examiner PC:** install agent **1.1.0** (same installer, same steps; it replaces 1.0.0). Agents 1.0.0 keep
  working on the office network; Polaron shows an "update the agent" note for them.

## Verification
- Real C# agent (Mono) through a real FastAPI/uvicorn server and real Redis, with the server given no direct address:
  manifest in 0.52 s; 22 MB image byte-identical; 100 random reads identical; read-only FUSE mount over the outbound
  connection with byte-identical SHA-256; agent restart resumed from the DPAPI-protected token; file changed on the
  PC refused (`EIO`); revoke through the outbound connection removed the share on the PC; a relay URL for a foreign
  origin was refused.
- Fixed during testing: a request taken by a poll whose connection had just dropped was lost until the full
  timeout (seen as a failed mount right after an agent restart). Now: disconnect check + requeue, and acknowledgements.
  Kill/restart scenario re-run 3 times: mount in 0.9-1.0 s each time (was 21 s or failing).
- `backend/tests/test_client_evidence_v1_21.py`: 39 tests (6 new for the outbound connection, through the real HTTP
  endpoints: exact bytes, lost request recovered within seconds, acknowledged slow upload not re-sent, token checks,
  attach falls back to the outbound connection). Full backend suite compared test by test with V1.20.1: no test that
  passed before fails now. Frontend: type-check and 33/33 tests.

## Not verified here
A real Windows PC over a real internet connection: Windows TLS and proxies, DPAPI on Windows (tested with Mono's
implementation), and a self-signed console certificate with `-TrustServerThumbprint`.

## First-run checklist (from outside the office)
1. On a home PC, open the Polaron console in the browser over HTTPS and log in.
2. Choose **This computer**; install agent 1.1.0 when prompted (or re-run the installer over 1.0.0).
3. Select a small E01 set. The success message and job card say "through this computer's outbound connection".
4. Put the PC to sleep for a minute during extraction: the card shows "Waiting for …", then extraction continues.
5. Delete the job: the share disappears from `polaron-client-evidence-agent.ps1 -Status` on the PC.
