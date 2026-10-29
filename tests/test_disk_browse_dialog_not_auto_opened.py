"""Disk jobs: the drive dialog opens only from "Browse drives".

The examiner must choose Standard forensic / Deep examination first; the profile
is sent when the folder is registered, so opening the dialog on arrival meant
cases were registered with the default profile before a choice was possible.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "frontend/src/pages/forensic/JobDetailPage.tsx"


def _auto_effect(source: str) -> str:
    start = source.index("const autoFolderOpened = useRef(false);")
    return source[start:source.index("}, [job, locationState.autoSelectFolder", start)]


def test_disk_jobs_scroll_to_panel_instead_of_opening_dialog():
    effect = _auto_effect(PAGE.read_text())
    disk_branch = effect[effect.index("if (!isMobileEvidenceJob(job, locationState.lockedSourceType)) {"):]
    disk_branch = disk_branch[:disk_branch.index("return () => window.clearTimeout(timer);")]
    assert "openEvidenceFolder" not in disk_branch
    assert "scrollIntoView" in disk_branch


def test_mobile_auto_open_is_unchanged():
    effect = _auto_effect(PAGE.read_text())
    tail = effect[effect.rindex("const timer = window.setTimeout(() => {"):]
    assert "evidencePanelRef.current?.openEvidenceFolder();" in tail


def test_browse_drives_button_still_opens_the_dialog():
    panel = (ROOT / "frontend/src/components/forensic/HostEvidencePanel.tsx").read_text()
    button = panel[panel.index("onClick={() => void openNativeFolderPicker()}", panel.index("Choose the folder from any available HDD")):]
    assert button.index("Browse drives") < 400


def test_profile_is_sent_with_the_folder_registration():
    panel = (ROOT / "frontend/src/components/forensic/HostEvidencePanel.tsx").read_text()
    # 2026-10-22: read from a ref. The plain state value was captured by a memoised
    # dialog callback and sent "standard" after Deep examination was selected.
    assert panel.count("processing_profile: processingProfileRef.current,") == 2
    assert "processing_profile: processingProfile," not in panel
