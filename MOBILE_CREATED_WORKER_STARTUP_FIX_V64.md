# V64 - Mobile created-worker startup/readiness fix

## Problem
Windows startup could fail with:

- `aetheris-mobile-ios-worker-parse-1 status=created health=none exit=0`
- `aetheris-mobile-ios-worker-build-1 status=created health=none exit=0`

Docker state `created` with exit code `0` is not a crashed container. It means Compose created the worker but it has not started yet, commonly while `depends_on` health conditions for the mobile API / CUDA probe are still settling.

The global readiness checker incorrectly classified every non-running, non-one-shot container as failed immediately.

## Fix
1. `created`, `restarting`, and `removing` are transitional/pending states during the readiness window.
2. Android and iOS startup now waits for the product `api` and `nvidia-cuda` dependencies.
3. If `worker-build` or `worker-parse` is still `created`, startup reconciles it with `docker compose up -d <service>` after the dependencies are healthy.
4. Real failures still fail startup: exited/dead core containers, unhealthy core containers after the readiness window, or containers that remain pending until timeout.
5. No evidence volumes or mobile case data are removed or recreated by this change.

## Validation
Focused V64 plus existing V60/V62 startup tests: 13/13 passed.
