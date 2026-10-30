from app.malware.app_names import app_display_name


def test_a_stored_label_is_the_application_name():
    assert app_display_name("w3bminds.engVarta.app", "ENGVARTA") == "ENGVARTA"


def test_messages_is_named_when_the_scan_only_has_the_package_id():
    assert app_display_name("com.android.mms", "") == "Messages"
    assert app_display_name("com.android.mms", None) == "Messages"


def test_an_unknown_package_without_a_label_stays_unnamed():
    assert app_display_name("com.example.unknown", None) is None
