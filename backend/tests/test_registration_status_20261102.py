from app.services.registration_status import registration_snapshot


def test_scope_same_file_names_to_independent_images(tmp_path):
    first = tmp_path / "case-a" / "image"
    second = tmp_path / "case-b" / "image"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    rows = [
        {"host_path": str(first / "evidence.E01"), "original_name": "evidence.E01"},
        {"host_path": str(first / "evidence.E02"), "original_name": "evidence.E02"},
        {"host_path": str(second / "evidence.E01"), "original_name": "evidence.E01"},
    ]
    a = registration_snapshot(rows, str(first), ["evidence.E01", "evidence.E02"])
    b = registration_snapshot(rows, str(second), ["evidence.E01", "evidence.E02"])
    assert a["complete"] and a["registered_count"] == 2
    assert not b["complete"] and b["registered_count"] == 1
    assert b["missing_names"] == ["evidence.E02"]


def test_empty_or_untrusted_expected_list_never_claims_completion(tmp_path):
    folder = str(tmp_path / "case")
    rows = [{"host_path": folder + "/image.E01", "original_name": "image.E01"}]
    assert registration_snapshot(rows, folder, [])["complete"] is False
    assert registration_snapshot(rows, str(tmp_path / "other"), ["image.E01"])["registered_count"] == 0


def test_case_insensitive_windows_matching():
    rows = [{"host_path": "G:/Evidence/CaseA/IMAGE.E01", "original_name": "IMAGE.E01"}]
    result = registration_snapshot(rows, "g:/evidence/casea", ["image.e01"])
    assert result["complete"]



def test_ingest_gate_executes_before_extraction_enqueue():
    """Source-order guard; route integration requires production psycopg2."""
    from pathlib import Path
    source = (Path(__file__).parents[1] / "app/routers/jobs.py").read_text()
    start = source.index("def ingest_host_path(")
    segment = source[start:source.index("@router.put", start)]
    guard = segment.index("if body.selected_names:")
    queue = segment.index("if body.auto_process and result[\"accepted\"]:")
    assert guard < queue
    assert "partial_segment_registration" in segment


def test_registration_status_endpoint_uses_source_scoped_snapshot():
    from pathlib import Path
    source = (Path(__file__).parents[1] / "app/routers/jobs.py").read_text()
    start = source.index("def evidence_registration_status(")
    segment = source[start:source.index('@router.post("/jobs/{job_id}/evidence/ingest-path")', start)]
    assert "registration_snapshot(rows, str(folder.resolve()), body.expected_names)" in segment
    assert "require_firm_permission(\"job:read\")" in source
