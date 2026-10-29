from pathlib import Path


def test_parse_heartbeat_does_not_scan_entire_ocr_table():
    path = Path(__file__).resolve().parents[1] / 'app' / 'services' / 'artifact_parse.py'
    source = path.read_text()
    start = source.index('    def _publish_scan(')
    end = source.index('    for part_uri, part_artifacts in by_part.items():', start)
    hotpath = source[start:end]
    assert 'count(*) FILTER (WHERE ocr_status' not in hotpath
    assert 'gpu_done, gpu_pending = 0, 0' in hotpath
    assert 'now - last_scan_beat < 10.0' in hotpath
