from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_greenbone_feed_containers_are_one_shot():
    text = (ROOT / 'docker-compose.gvm.yml').read_text(encoding='utf-8-sig')
    assert 'KEEP_ALIVE' not in text
    for svc in ('vulnerability-tests','notus-data','scap-data','cert-bund-data','dfn-cert-data','data-objects','report-formats'):
        assert f'{svc}:' in text
    assert 'condition: service_completed_successfully' in text


def test_startup_uses_phased_vulnerability_boot():
    text = (ROOT / 'script_docker' / 'start_docker.ps1').read_text(encoding='utf-8-sig')
    assert 'function Start-VulnerabilityStackPhased' in text
    assert 'function Invoke-VulnOneShot' in text
    assert "foreach ($name in @('forensic', 'mobile-android', 'mobile-ios'))" in text
    assert 'Start-VulnerabilityStackPhased -ComposeArgs $vulnArgs' in text
    assert "@('redis-gvm','pg-gvm')" in text
    assert "@('openvas','openvasd','ospd-openvas','gvmd','gvm-tools')" in text


def test_global_readiness_does_not_fail_on_scanner_warmup():
    text = (ROOT / 'script_docker' / 'start_docker.lib.ps1').read_text(encoding='utf-8-sig')
    assert '$optionalServices' in text
    for svc in ('gvmd','openvasd','ospd-openvas','zap','trivy'):
        assert f'"{svc}"' in text
    assert 'OptionalFailed' in text
    assert '$warmupServices' in text


def test_modified_compose_files_parse():
    for rel in ('docker-compose.gvm.yml','docker-compose.vuln-scanners.yml','services/vuln/docker-compose.yml'):
        data = yaml.safe_load((ROOT / rel).read_text(encoding='utf-8-sig'))
        assert isinstance(data, dict)
        assert 'services' in data


def test_compose_environment_sections_are_mappings_not_null():
    for rel in ('docker-compose.gvm.yml','docker-compose.vuln-scanners.yml','services/vuln/docker-compose.yml'):
        data = yaml.safe_load((ROOT / rel).read_text(encoding='utf-8-sig'))
        for name, service in (data.get('services') or {}).items():
            if 'environment' in service:
                assert isinstance(service['environment'], (dict, list)), f"{rel}:{name}.environment must not be null"
