"""Regression checks: same-named E01 segments from distinct sources must not merge."""

from app.services.disk import segment_readiness
from app.services.next_evidence_directory import pending_directories, restrict_to_next_directory
from app.services.virtual_disk import directory_namespace, list_image_directories


def _files():
    return [
        {"original_name": "image.E01", "host_path": "/cases/A/images/image.E01", "sha256": "same"},
        {"original_name": "image.E02", "host_path": "/cases/A/images/image.E02", "sha256": "same"},
        {"original_name": "image.E01", "host_path": "/cases/B/images/image.E01", "sha256": "same"},
        {"original_name": "image.E02", "host_path": "/cases/B/images/image.E02", "sha256": "same"},
        {"original_name": "image.E01", "host_path": "/cases/C/images/image.E01", "sha256": "same"},
    ]


def test_three_identical_names_are_three_images_not_duplicates():
    groups = list_image_directories(_files())
    assert len(groups) == 3
    assert len({g["namespace"] for g in groups}) == 3
    assert [len(g["paths"]) for g in groups] == [2, 2, 1]
    assert all(g["label"] == "images" for g in groups)
    assert all(namespace.startswith("images--") for namespace in (g["namespace"] for g in groups))


def test_same_name_e01_sets_have_independent_readiness_and_gaps():
    state = segment_readiness(_files())
    assert state["ready"]
    assert len(state["disk_sets"]) == 3
    assert len({r["source_directory"] for r in state["disk_sets"]}) == 3
    broken = [f for f in _files() if f["host_path"] != "/cases/B/images/image.E01"]
    state = segment_readiness(broken)
    assert not state["ready"]
    assert len(state["disk_sets"]) == 3
    assert len(state["gaps"]) == 1
    assert state["gaps"][0]["source_directory"] == "/cases/B/images"
    assert state["gaps"][0]["missing_segments"] == [1]


def test_directory_preference_not_sorted_by_duplicate_filename():
    order = ["/cases/C/images", "/cases/B/images", "/cases/A/images"]
    first, log_line = restrict_to_next_directory(_files(), directories=order)
    assert [item["host_path"] for item in first] == ["/cases/C/images/image.E01"]
    assert "Directory 1 of 3" in log_line
    pending = pending_directories(_files(), [first[0]["host_path"]], directories=order)
    assert [g["directory"] for g in pending] == order[1:]


def test_single_directory_and_same_directory_retries_do_not_duplicate():
    files = _files()[:2]
    first, log_line = restrict_to_next_directory(files)
    assert first == files and log_line is None
    assert pending_directories(files, [f["host_path"] for f in files]) == []
    assert directory_namespace("/cases/A/images") == directory_namespace("/cases/A/images/")
    assert directory_namespace("/cases/A/images") != directory_namespace("/cases/B/images")


def test_appended_publish_combines_index_without_deduping_different_sources(monkeypatch):
    import json
    import sys
    from types import SimpleNamespace
    # Test index semantics without depending on the container's optional zstd wheel.
    class IdentityCodec:
        def __init__(self, *args, **kwargs):
            pass
        def compress(self, data):
            return data
        def decompress(self, data):
            return data
    monkeypatch.setitem(sys.modules, "zstandard", SimpleNamespace(
        ZstdCompressor=IdentityCodec, ZstdDecompressor=IdentityCodec,
    ))
    from app.services.next_evidence_directory import _publish_directory
    from app.services.virtual_disk import list_image_directories
    import app.db.sql_helpers as dbhelpers
    import app.services.disk_manifest as disk_manifest
    import app.services.storage as storage

    saved = {}
    writes = []
    def put(key, data, content_type=None):
        saved[key] = data
        return f"minio://{key}"
    monkeypatch.setattr(storage, "put_bytes", put)
    monkeypatch.setattr(dbhelpers, "fetchone", lambda *args, **kwargs: {"disk_source": {"source_type": "disk"}})
    monkeypatch.setattr(dbhelpers, "execute", lambda db, sql, params: writes.append(params))
    monkeypatch.setattr(disk_manifest, "disk_prefix", lambda job_id: f"jobs/{job_id}/extracted-disk")
    monkeypatch.setattr(disk_manifest, "load_index_entries", lambda manifest: [
        json.loads(line) for line in saved[manifest["index_uri"].removeprefix("minio://")].decode().splitlines()
    ])
    manifest = {"files_extracted": 1, "bytes_extracted": 5, "index_uri": "minio://jobs/job/extracted-disk/index.jsonl.zst", "parts_map": {"0": "minio://one"},
                "segment_paths": ["/cases/A/images/image.E01"], "directory_stats": []}
    # Mock the starting source's already-published index.
    saved["jobs/job/extracted-disk/index.jsonl.zst"] = b'{"path":"images--a/data.txt","part_id":0,"offset":0}'
    groups = list_image_directories(_files())
    for index, group in enumerate(groups[1:], 1):
        manifest = _publish_directory(
            SimpleNamespace(commit=lambda: None), "job", manifest=manifest, group=group,
            new_entries=[{"path": f"{group['namespace']}/data.txt", "part_id": index, "offset": 0}],
            parts_map={str(index): f"minio://part-{index}"}, files_added=1, bytes_added=5,
            skipped_added=0, filter_stats={}, compressor=IdentityCodec(),
        )
    combined = disk_manifest.load_index_entries(manifest)
    assert len(combined) == 3
    # Original committed index remains immutable through both appends.
    assert saved["jobs/job/extracted-disk/index.jsonl.zst"] == b'{"path":"images--a/data.txt","part_id":0,"offset":0}'
    assert manifest["index_uri"].endswith(f"{groups[2]['namespace']}.jsonl.zst")
    assert len({row["path"] for row in combined}) == 3
    assert manifest["files_extracted"] == 3
    assert manifest["directory_materialize_pending"] is True
    assert len(manifest["directory_stats"]) == 2
    assert len(manifest["parts_map"]) == 3
    assert len(writes) == 2
    assert manifest["index_uri"] != "minio://jobs/job/extracted-disk/index.jsonl.zst"
    assert writes[-1]["uri"].endswith(f"{groups[2]['namespace']}.json")


def test_downstream_barrier_waits_for_recoverable_materialization(monkeypatch):
    from app.services.next_evidence_directory import unfinished_directory_reason
    import app.db.sql_helpers as helpers

    files = _files()
    monkeypatch.setattr(helpers, "fetchall", lambda *args, **kwargs: files)
    manifest = {
        "segment_paths": [file["host_path"] for file in files],
        "evidence_folders": ["/cases/A/images", "/cases/B/images", "/cases/C/images"],
        "directory_materialize_pending": True,
    }
    assert "registration starts after" in unfinished_directory_reason(
        None, "job", {"disk_source": manifest}
    )
    manifest.pop("directory_materialize_pending")
    assert unfinished_directory_reason(None, "job", {"disk_source": manifest}) is None
