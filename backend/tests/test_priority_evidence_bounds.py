"""Disk priority evidence must not re-read every extracted file."""

from app.services.forensic_priority_evidence import priority_source_kind


def test_breadcrumb_and_empty_files_are_not_read():
    path = "ProgramData/Microsoft/NetFramework/BreadcrumbStore/netcore/YourPhone/YPP.Common.0.23092.35"
    assert priority_source_kind(path, 4096, ["forensic_fallback"]) == "skip"
    assert priority_source_kind(path, 0, ["browser_parser"]) == "skip"
    assert priority_source_kind("Windows/Temp/ShaderCache/blob.bin", 1000, ["communication_evidence"]) == "skip"


def test_unrecognized_files_and_generic_documents_do_not_open_the_shard():
    assert priority_source_kind("Windows/System32/drivers/foo.sys", 100, ["forensic_fallback"]) == "skip"
    assert priority_source_kind("Windows/WinSxS/manifest.xml", 2000, ["communication_evidence"]) == "skip"
    assert priority_source_kind("Program Files/App/settings.json", 4000, ["communication_evidence"]) == "skip"


def test_real_priority_sources_are_still_read_once():
    assert priority_source_kind("Users/a/AppData/places.sqlite", 5000, ["browser_parser"]) == "read"
    assert priority_source_kind("Users/a/Documents/mail/inbox.eml", 2000, ["communication_evidence"]) == "read"
    assert priority_source_kind("Users/a/Downloads/WhatsApp/export.json", 2000, ["communication_evidence"]) == "read"
    assert priority_source_kind("Users/a/Desktop/page.html", 1000, [], web_text=True) == "read"


def test_media_metadata_does_not_require_archive_bytes():
    assert priority_source_kind("Users/a/Pictures/a.png", 1000, ["files_media_parser"]) == "metadata"
