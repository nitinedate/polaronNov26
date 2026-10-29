# Laptop Scanner V1.9.4 — the 40-second NVT probe

Build stamp: `1.9.4-v54.0`. Cumulative: includes V1.9.1, V1.9.2 and V1.9.3.

## What the first V1.9.3 job showed (job d1c55fbe, 192.168.0.163)

One IP start still took 55 s (`start_attempt` 12:45:13 → `started` 12:46:07). The
config read that V1.9.3 removed took 0.6 s here ("Effective check selection" logged
0.6 s after the profile config), so it was **not** the slow step — the V1.9.3 notes
were wrong about that. The 39.5 s gap came after it, in the feed-health probe:

`_feed_health()` called `get_nvts(filter_string="rows=1 first=1", extended=True)`.
python-gvm 27 sends that as a bare `<get_nvts/>` — the filter is dropped — so gvmd
built and returned all 185,633 checks every time. The same probe also runs in the
agent's readiness check about once a minute, so gvmd was doing this continuously,
including while scans ran.

## Change

`agent/gmp_local.py` `_feed_health()` now asks `get_nvts(filter_string="rows=1 first=1")`
(sent as `<get_info type="NVT" filter="rows=1 first=1"/>`, total in `<info_count>`),
and if that has no total, sums `max_nvt_count` from `get_nvt_families` (one row per
family). It never requests the full list. Readiness rules are unchanged.

## Upgrade

Same as V1.9.3 (extract over the install, keep `.env`, `logs\`, `runtime\`), then:
```powershell
docker compose up -d --force-recreate --no-deps scanner-agent
docker compose logs --tail 80 scanner-agent | Select-String "AGENT BUILD|NVT timeout index"
```
`--force-recreate` is required: it also adds the `gvm_vt_data` mount that V1.9.3
introduced (job d1c55fbe still logged "index unavailable: plugins not readable").

Expected: `AGENT BUILD 1.9.4-v54.0`, then `NVT timeout index ... building`/`built`.
On the next job, `start_attempt` → `started` should be well under the previous 55 s.

## Testing

395 agent tests pass. The V1.4.8 test that required `extended=True` is replaced by
two tests: the probe sends only the filtered request, and it falls back to family
totals — never to the full list.
