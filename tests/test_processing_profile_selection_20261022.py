"""2026-10-22: Deep examination selected in the UI must be the profile the job runs."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

PANEL = (ROOT / "frontend/src/components/forensic/HostEvidencePanel.tsx").read_text(encoding="utf-8")
API = (ROOT / "frontend/src/lib/forensicApi.ts").read_text(encoding="utf-8")
PAGE = (ROOT / "frontend/src/pages/forensic/JobDetailPage.tsx").read_text(encoding="utf-8")
JOBS = (ROOT / "backend/app/routers/jobs.py").read_text(encoding="utf-8")


def test_ingest_payloads_read_profile_from_ref_not_closure():
    # The stale closure sent the first-render value ("standard").
    assert "processing_profile: processingProfile," not in PANEL
    assert PANEL.count("processing_profile: processingProfileRef.current") == 2


def test_browse_dialog_calls_latest_register_function():
    body = PANEL[PANEL.index("const confirmStagedBrowseFolders = useCallback("):]
    body = body[: body.index("\n  );") + 4]
    assert "registerPickedFolderRef.current(folder, { deferProcessing: !last })" in body
    assert "does not yet support one-job multi-source extraction" not in body
    assert "await registerPickedFolder(folders[0])" not in body
    assert "registerPickedFolderRef.current = registerPickedFolder;" in PANEL


def test_profile_change_is_persisted_and_lockable():
    assert "forensicApi.setProcessingProfile(jobId, next)" in PANEL
    assert re.search(r"disabled=\{registering \|\| profileSaving \|\| Boolean\(processingProfileLocked\)\}", PANEL)
    assert "setProcessingProfile: (jobId: string" in API and "/processing-profile" in API
    assert "initialProcessingProfile=" in PAGE and "processingProfileLocked=" in PAGE


def test_backend_endpoint_and_no_standard_default():
    from app.schemas.forensic import IngestPathBody

    assert IngestPathBody().processing_profile is None
    assert '@router.put("/jobs/{job_id}/processing-profile")' in JOBS
    assert 'if body.processing_profile not in ("standard", "deep")' not in JOBS


@pytest.mark.parametrize("requested,stored,expected", [
    ("deep", None, "deep"),
    ("standard", "deep", "standard"),   # explicit choice wins
    (None, "deep", "deep"),             # stored examiner choice is kept
    ("", "deep", "deep"),
    (None, None, "standard"),
    (None, "garbage", "standard"),
    ("DEEP", None, "deep"),
])
def test_resolve_ingest_profile(requested, stored, expected):
    from app.services.processing_profile import resolve_ingest_profile

    assert resolve_ingest_profile(requested, stored) == expected


def test_invalid_profile_rejected():
    from app.services.processing_profile import normalize_requested_profile

    with pytest.raises(ValueError):
        normalize_requested_profile("fast")
