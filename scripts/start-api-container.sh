#!/bin/sh
# Robust API container bootstrap for Aetheris / Polaron.
# Usage: /scripts/start-api-container.sh app.main:app
set -eu

APP_ROOT="${AETHERIS_APP_ROOT:-/app}"
ASGI_APP="${1:-app.main:app}"
PORT="${PORT:-8080}"

if [ ! -d "$APP_ROOT/app" ] || [ ! -f "$APP_ROOT/app/__init__.py" ]; then
  echo "FATAL: Python application package is missing at $APP_ROOT/app" >&2
  echo "Container cwd: $(pwd)" >&2
  echo "Contents of $APP_ROOT:" >&2
  ls -la "$APP_ROOT" >&2 2>/dev/null || true
  exit 78
fi

if [ ! -f "$APP_ROOT/alembic.ini" ]; then
  echo "FATAL: Alembic config is missing at $APP_ROOT/alembic.ini" >&2
  exit 78
fi

export PYTHONPATH="$APP_ROOT${PYTHONPATH:+:$PYTHONPATH}"
cd "$APP_ROOT"
mkdir -p "$APP_ROOT/data/tmp"

# Migrations are idempotent. Preserve the historical fail-open behavior for a
# temporarily locked database, but always use the correct config/root.
if ! alembic -c "$APP_ROOT/alembic.ini" upgrade head; then
  echo "WARN: Alembic migration returned non-zero; continuing to SQL helper bootstrap." >&2
fi

if ! python /scripts/ensure_sql_functions.py; then
  echo "WARN: ensure_sql_functions.py returned non-zero; API startup will continue." >&2
fi

if ! python /scripts/bootstrap_platform_admin.py; then
  echo "WARN: bootstrap_platform_admin.py returned non-zero; API startup will continue." >&2
fi

# Validate import before handing PID 1 to uvicorn. This gives an actionable
# error instead of a generic 'Could not import module app.main'.
python - "$ASGI_APP" <<'PY'
import importlib
import sys
spec = sys.argv[1]
module_name = spec.split(":", 1)[0]
importlib.import_module(module_name)
print(f"API import preflight OK: {module_name}")
PY

exec uvicorn "$ASGI_APP" --app-dir "$APP_ROOT" --host 0.0.0.0 --port "$PORT"
