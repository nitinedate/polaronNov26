"""Standard examination profile — extraction scope.

Standard must keep every named forensic artifact and all user-space evidence,
and drop only OS / vendor trees and vendor application assets. Each drop carries
a rule id so it is recorded in the extraction manifest's filter_stats.
"""

import pytest

from app.services.extract_filters import should_extract_node_v2
from app.services.extract_os_vendor_noise import classify_os_vendor_standard

MAX = 2_147_483_648
UNCERTAIN = 4_194_304


def standard_decision(path: str, size: int) -> tuple[bool, str | None]:
    """Mirror of extracted_disk._filter_nodes for mode='standard'."""
    rule = classify_os_vendor_standard(path, size_bytes=size, os_family="windows")
    if rule:
        return False, rule
    return should_extract_node_v2(
        path, size, mode="standard", max_file_bytes=MAX,
        os_family="windows", uncertain_max_bytes=UNCERTAIN,
    )


MUST_KEEP = [
    ("Windows/System32/config/SYSTEM", 12_000_000),
    ("Windows/System32/config/SOFTWARE", 80_000_000),
    ("Windows/System32/config/SAM", 65_536),
    ("Windows/System32/config/SECURITY", 65_536),
    ("Users/alice/NTUSER.DAT", 3_000_000),
    ("Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat", 1_000_000),
    ("Windows/appcompat/Programs/Amcache.hve", 2_000_000),
    ("Windows/System32/sru/SRUDB.dat", 20_000_000),
    ("Windows/System32/winevt/Logs/Security.evtx", 20_000_000),
    ("Windows/Prefetch/CHROME.EXE-1234ABCD.pf", 40_000),
    ("Windows/INF/setupapi.dev.log", 2_000_000),
    ("Windows/Panther/unattend.xml", 8_000),
    ("Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag", 4_000),
    ("Windows/System32/drivers/etc/hosts", 900),
    ("Windows/Temp/dropper.ps1", 3_000),
    ("ProgramData/Microsoft/Windows Defender/Support/MPLog-20260101.log", 500_000),
    ("ProgramData/Microsoft/Windows/Start Menu/Programs/Chrome.lnk", 2_000),
    ("Program Files/CompanyApp/export/customers.csv", 400_000),
    ("Program Files/CompanyApp/logs/app.log", 100_000),
    ("Program Files (x86)/Tool/config.ini", 800),
    ("Users/alice/Documents/RRP_pricing.xlsx", 300_000),
    ("Users/alice/Desktop/notes.txt", 2_000),
    ("Users/alice/Downloads/setup_tool.exe", 3_000_000),
    ("Users/alice/AppData/Local/Temp/run.ps1", 4_000),
    ("Users/alice/AppData/Local/Google/Chrome/User Data/Default/History", 5_000_000),
    ("Users/alice/AppData/Local/Microsoft/Outlook/alice@corp.com.ost", 900_000_000),
    ("Users/alice/AppData/Roaming/Microsoft/Windows/Recent/report.docx.lnk", 1_500),
    ("Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
     "5f7b5f1e01b83767.automaticDestinations-ms", 30_000),
    ("Users/alice/Pictures/IMG_0001.jpg", 2_000_000),
    ("Users/alice/OneDrive/Contracts/NDA.pdf", 200_000),
    ("$Recycle.Bin/S-1-5-21-1/$IABC123.docx", 500),
    # UWP package state is user evidence (exempt from the V45 packages rule).
    ("Users/alice/AppData/Local/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/"
     "LocalState/shared/transfers/IMG-2026.jpg", 50_000),
    ("Users/alice/AppData/Local/Packages/Microsoft.YourPhone_8wekyb3d8bbwe/"
     "LocalCache/Indexed/abc/User/Photos/PhotosCache/1.jpg", 50_000),
    ("Users/alice/AppData/Local/Packages/Microsoft.YourPhone_8wekyb3d8bbwe/"
     "LocalCache/Indexed/abc/System/Database/phone.db", 50_000),
    ("Users/alice/AppData/Local/Packages/microsoft.windowscommunicationsapps_8wekyb3d8bbwe/"
     "LocalState/HxStore.hxd", 50_000),
    ("Users/alice/AppData/Local/Packages/Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe/"
     "LocalState/plum.sqlite", 50_000),
]

MUST_DROP = [
    ("Windows/WinSxS/amd64_microsoft-windows-foo_31bf3856ad364e35_10.0.19041.1_none_abc/foo.dll", 300_000),
    ("Windows/WinSxS/Manifests/amd64_foo.manifest", 3_000),
    ("Windows/System32/kernel32.dll", 400_000),
    ("Windows/System32/en-US/shell32.dll.mui", 100_000),
    ("Windows/SysWOW64/msvcrt.dll", 300_000),
    ("Windows/Fonts/arial.ttf", 900_000),
    ("Windows/SystemApps/Microsoft.Windows.Search_cw5n1h2txyewy/Assets/logo.png", 4_000),
    ("Program Files/Google/Chrome/Application/120.0.6099.71/resources.pak", 9_000_000),
    ("Program Files/Microsoft Office/root/Office16/WINWORD.EXE", 2_000_000),
    ("Program Files/WindowsApps/Microsoft.People_10.0/Assets/StoreLogo.png", 3_000),
    ("Program Files (x86)/Microsoft/Edge/Application/msedge.dll", 3_000_000),
    ("Program Files/nodejs/node_modules/npm/lib/cli.js", 4_000),
    ("Program Files/Adobe/Acrobat/Locale/en_US/strings.json", 20_000),
    ("ProgramData/Package Cache/{GUID}/vc_redist.x64.exe", 20_000_000),
    ("Users/alice/AppData/Local/Programs/Microsoft VS Code/Code.exe", 100_000_000),
    ("Users/alice/project/node_modules/lodash/lodash.js", 500_000),
]


@pytest.mark.parametrize("path,size", MUST_KEEP)
def test_standard_keeps_forensic_and_user_evidence(path, size):
    ok, reason = standard_decision(path, size)
    assert ok, f"Standard dropped evidence {path!r} ({reason})"


@pytest.mark.parametrize("path,size", MUST_DROP)
def test_standard_drops_vendor_noise_with_a_recorded_rule(path, size):
    ok, reason = standard_decision(path, size)
    assert not ok, f"Standard kept vendor noise {path!r}"
    assert reason, "every exclusion must carry a rule id for filter_stats"


@pytest.mark.parametrize("path,size", MUST_KEEP)
def test_deep_full_mode_keeps_everything_standard_keeps(path, size):
    ok, _ = should_extract_node_v2(path, size, mode="full", max_file_bytes=MAX,
                                   os_family="windows", uncertain_max_bytes=UNCERTAIN)
    assert ok


def test_defensible_and_forensic_modes_are_unchanged_by_standard_rules():
    # The shared modes used by other entry points must not inherit Standard's exclusions.
    for mode in ("defensible", "full"):
        ok, _ = should_extract_node_v2("Windows/System32/kernel32.dll", 400_000, mode=mode,
                                       max_file_bytes=MAX, os_family="windows",
                                       uncertain_max_bytes=UNCERTAIN)
        assert ok, mode
