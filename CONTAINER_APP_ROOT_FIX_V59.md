# V59 — Container application-root / Alembic / ASGI startup fix

## Failure addressed

The API container could start with a working directory that was not `/app`, producing:

- `No config file 'alembic.ini' found`
- `ModuleNotFoundError: No module named 'app.db'`
- `ModuleNotFoundError: No module named 'app.config'`
- `Error loading ASGI app. Could not import module \"app.main\"`

The project files were present; startup was relying on an implicit working directory and helper scripts assumed a repository `/backend` path that does not exist inside the runtime container.

## V59 behavior

All API stacks now use `/scripts/start-api-container.sh`.

The bootstrap explicitly:

1. validates `/app/app/__init__.py` and `/app/alembic.ini`;
2. exports `PYTHONPATH=/app`;
3. changes directory to `/app`;
4. runs `alembic -c /app/alembic.ini upgrade head`;
5. executes SQL-function and platform-admin bootstraps with a container-aware backend-root resolver;
6. imports the requested ASGI module as a preflight;
7. `exec`s Uvicorn with `--app-dir /app`.

The same startup contract is used by central forensic, HTTPS central forensic, Android, iPhone, mobile-extract legacy, and vulnerability API stacks.

The startup required-files manifest includes the new bootstrap script, so an incomplete package is rejected before Docker startup.
