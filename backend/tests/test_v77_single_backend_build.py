from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

COMPOSE_FILES = {
    "forensic": ROOT / "docker-compose.yml",
    "android": ROOT / "services/mobile-android/docker-compose.yml",
    "ios": ROOT / "services/mobile-ios/docker-compose.yml",
    "mobile-extract": ROOT / "services/mobile-extract/docker-compose.yml",
}

EXPECTED = {
    "forensic": ("rag_new2-api", "api"),
    "android": ("aetheris-mobile-android-app", "api"),
    "ios": ("aetheris-mobile-ios-app", "api"),
    "mobile-extract": ("rag_new2-api", "api"),
}


def _load(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_backend_images_have_exactly_one_builder_per_stack():
    for name, path in COMPOSE_FILES.items():
        data = _load(path)
        image, expected_builder = EXPECTED[name]
        services = data.get("services") or {}
        users = {
            svc: cfg
            for svc, cfg in services.items()
            if isinstance(cfg, dict) and cfg.get("image") == image
        }
        assert users, f"{name}: no services reference {image}"
        builders = [svc for svc, cfg in users.items() if "build" in cfg]
        assert builders == [expected_builder], (
            f"{name}: {image} must be built once by {expected_builder}; "
            f"found builders={builders}"
        )


def test_worker_services_do_not_inherit_backend_build():
    for name, path in COMPOSE_FILES.items():
        data = _load(path)
        image, _ = EXPECTED[name]
        for svc, cfg in (data.get("services") or {}).items():
            if not isinstance(cfg, dict) or svc == "api" or cfg.get("image") != image:
                continue
            assert "build" not in cfg, f"{name}:{svc} must reuse {image}, not rebuild it"


def test_mobile_extract_api_uses_cuda_torch_build_arg():
    data = _load(COMPOSE_FILES["mobile-extract"])
    args = (((data["services"]["api"].get("build") or {}).get("args")) or {})
    assert "TORCH_INDEX_URL" in args
