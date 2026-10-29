# Vulnerability Compose schema fix V61

## Failure
Docker Compose rejected `docker-compose.gvm.yml` with:

`services.cert-bund-data.environment must be a mapping`

## Root cause
V60 intentionally removed `KEEP_ALIVE=1` from Greenbone one-shot feed containers, but four services were left with an empty YAML key:

```yaml
environment:
```

YAML parses that value as `null`. Docker Compose requires `environment` to be a mapping or list when the key exists.

Affected services:
- `notus-data`
- `scap-data`
- `cert-bund-data`
- `dfn-cert-data`

## V61 change
The empty `environment:` keys were removed entirely. Services that actually require variables retain normal mapping-form environment blocks.

A regression test now walks the relevant vulnerability Compose files and fails if any service contains a null `environment` value.

## Validation
`tests/test_vuln_startup_phased_v60.py`: 5/5 passed.

The build environment used for packaging does not provide the Docker CLI, so `docker compose config` itself could not be executed here. The same structures that Docker rejected are now parsed and schema-checked in the regression suite, and the specific null environment values are gone.
