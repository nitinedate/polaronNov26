from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_root_compose_has_single_top_level_sections_and_rag_workers_are_services():
    text = (ROOT / 'docker-compose.yml').read_text(encoding='utf-8')
    assert sum(1 for line in text.splitlines() if line == 'volumes:') == 1
    assert sum(1 for line in text.splitlines() if line == 'networks:') == 1
    data = yaml.safe_load(text)
    assert isinstance(data, dict)
    services = data.get('services') or {}
    assert 'worker-rag-prep' in services
    assert 'worker-rag-gpu' in services
    assert 'worker-ocr-gpu' in services
    assert 'worker-beat' in services
    assert 'evidence_staging' in (data.get('volumes') or {})
    assert 'aetheris-common' in (data.get('networks') or {})


def test_forensic_compose_include_resolves_root_compose_name():
    data = yaml.safe_load((ROOT / 'services/forensic/docker-compose.yml').read_text(encoding='utf-8'))
    assert data['name'] == 'aetheris-forensic'
    assert data['include'] == ['docker-compose.yml']
