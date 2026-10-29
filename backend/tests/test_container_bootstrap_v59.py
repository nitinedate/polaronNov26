from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[2]


def test_api_bootstrap_script_is_required_and_present():
    manifest = json.loads((ROOT / "script_docker/start_docker.required-files.json").read_text())
    assert "scripts/start-api-container.sh" in manifest["common"]
    script = ROOT / "scripts/start-api-container.sh"
    assert script.is_file()
    text = script.read_text()
    assert 'APP_ROOT="${AETHERIS_APP_ROOT:-/app}"' in text
    assert 'alembic -c "$APP_ROOT/alembic.ini" upgrade head' in text
    assert 'export PYTHONPATH="$APP_ROOT${PYTHONPATH:+:$PYTHONPATH}"' in text
    assert 'exec uvicorn "$ASGI_APP" --app-dir "$APP_ROOT"' in text


def test_every_api_compose_uses_explicit_bootstrap():
    targets = {
        "docker-compose.yml": "app.main:app",
        "docker-compose.https.yml": "app.main:app",
        "services/mobile-android/docker-compose.yml": "app.main_mobile_android:app",
        "services/mobile-ios/docker-compose.yml": "app.main_mobile_ios:app",
        "services/mobile-extract/docker-compose.yml": "app.main_mobile_extract:app",
        "services/vuln/docker-compose.yml": "app.main_vuln:app",
    }
    for rel, app in targets.items():
        text = (ROOT / rel).read_text(encoding="utf-8-sig")
        assert f'command: ["/scripts/start-api-container.sh", "{app}"]' in text
        # The old cwd-dependent startup sequence must not remain for the API.
        assert not re.search(r'command:\s*>\s*\n\s*sh -c ".*?alembic upgrade head', text, re.S)


def test_bootstrap_helpers_resolve_app_root():
    for rel in ("scripts/ensure_sql_functions.py", "scripts/bootstrap_platform_admin.py"):
        text = (ROOT / rel).read_text()
        assert 'AETHERIS_APP_ROOT' in text
        assert 'Path(os.environ.get("AETHERIS_APP_ROOT", "/app"))' in text
        assert '(candidate / "app" / "__init__.py").is_file()' in text
