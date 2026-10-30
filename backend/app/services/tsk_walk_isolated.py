"""Bounded, restartable TSK filesystem enumeration in a disposable subprocess.

pytsk3/libewf are native extensions: a Python watchdog thread cannot interrupt
one blocked inside a filesystem call. Isolate *only* the walk; the main process
retains its extraction lease and commits no partial/unchecked enumeration data.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


class TSKWalkTimeout(RuntimeError):
    """The isolated source reader stopped producing useful enumeration progress."""


def _child(config_file: Path, result_file: Path) -> int:
    from app.services.virtual_disk import enumerate_all_files, open_virtual_disk_from_paths

    plan = json.loads(config_file.read_text(encoding="utf-8"))

    state = {"reader_phase": "reopening_evidence"}

    def progress(message: str, metadata: dict | None = None) -> None:
        if metadata and metadata.get("reader_phase"):
            state["reader_phase"] = str(metadata["reader_phase"])
        print(json.dumps({"kind": "progress", "message": message, "metadata": metadata or {}}, default=str), flush=True)

    if plan.get("inventory_workers_override") is not None:
        # This changes ONLY the disposable reader process, never Celery/global config.
        os.environ["EXTRACT_TSK_ENUM_WORKERS"] = str(plan["inventory_workers_override"])
    vd = open_virtual_disk_from_paths(
        plan["job_id"], plan["segment_paths"], hashes=plan.get("segment_hashes"),
        base_name=plan.get("base_name") or "", fmt=plan.get("format") or "",
    )
    try:
        if vd._fs_info is None:
            raise RuntimeError("TSK filesystem could not be reopened in isolated reader; evidence was not enumerated")
        image = vd._img_info
        if image is not None and hasattr(image, "set_read_diagnostic"):
            image.set_read_diagnostic(progress, state)
        nodes = enumerate_all_files(
            vd, on_progress=progress,
            progress_interval_sec=float(plan.get("report_seconds") or 10),
            root_open_strategy=str(plan.get("root_open_strategy") or "inode"),
        )
        with result_file.open("w", encoding="utf-8") as target:
            for node in nodes:
                target.write(json.dumps(node, ensure_ascii=True, separators=(",", ":")) + "\n")
        print(json.dumps({"kind": "done", "count": len(nodes)}), flush=True)
        return 0
    finally:
        vd.close()


def _stop_owned_child(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def enumerate_tsk_isolated(vd, *, on_progress=None, schema_name: str | None = None,
                            idle_timeout_sec: float | None = None, retries: int | None = None,
                            root_idle_timeout_sec: float | None = None) -> list[dict]:
    """Return full nodes or fail closed. Never mistake a partial walk for completion.

    On a frozen C call, terminate only the child PID and safely restart the
    read-only walk. Do not terminate Celery, DB connections, other jobs, or GPU.
    """
    from app.services.virtual_disk import vd_plan

    idle = max(60.0, float(idle_timeout_sec if idle_timeout_sec is not None
                           else os.environ.get("EXTRACT_TSK_IDLE_TIMEOUT_SEC", "420")))
    root_idle = max(60.0, float(root_idle_timeout_sec if root_idle_timeout_sec is not None
                                  else os.environ.get("EXTRACT_TSK_ROOT_IDLE_TIMEOUT_SEC", "240")))
    # If the first PARALLEL root open fails, retrying parallel with only a
    # different inode/path argument repeats the same expensive libtsk I/O.
    # First fall back to the serial walker, which previously succeeded on
    # some multi-segment E01 images; only then alternate the root method.
    configured_readers = str(os.getenv("EXTRACT_TSK_ENUM_WORKERS", "2")).strip().lower()
    parallel_enabled = configured_readers not in {"0", "1", "off", "false", "no", "serial"}
    default_attempts = "3" if parallel_enabled else "2"
    attempts = max(1, min(3, int(retries if retries is not None
                                  else os.environ.get("EXTRACT_TSK_WALK_ATTEMPTS", default_attempts))))
    plan = {**vd_plan(vd), "job_id": vd.job_id, "report_seconds": 10}
    # open_dir(path='/') is the stall on multi-segment E01 images: TSK resolves
    # the root name with seeks tens of gigabytes apart and returns no entry.
    # Always open by inode first. Path is only the last fallback.
    preferred = "inode"
    alternate = "path"
    root_cap = max(root_idle, float(os.environ.get("EXTRACT_TSK_ROOT_MAX_SEC", "900")))
    # A large E01 can spend longer than root_cap inside libewf while the read
    # offset is still moving. That is progress. Only a silent open is capped
    # at root_cap; an open that keeps reading may continue until absolute_cap.
    absolute_cap = max(root_cap, float(os.environ.get("EXTRACT_TSK_ROOT_ABSOLUTE_SEC", "14400")))
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        # Parallel -> serial (same inode method) -> serial path fallback.
        # The root is always opened in ONE child, never shared between handles.
        serial_fallback = parallel_enabled and attempt > 1
        root_method = alternate if (attempt == 3 or (not parallel_enabled and attempt == 2)) else preferred
        inventory_mode = "serial" if (serial_fallback or not parallel_enabled) else "parallel"
        attempt_started = datetime.now(timezone.utc).isoformat()
        with tempfile.TemporaryDirectory(prefix="polaron-tsk-") as scratch:
            folder = Path(scratch)
            config_path = folder / "plan.json"
            nodes_path = folder / "nodes.jsonl"
            error_path = folder / "reader.stderr"
            config_path.write_text(json.dumps({**plan, "root_open_strategy": root_method,
                "inventory_workers_override": 1 if serial_fallback else None}), encoding="utf-8")
            message_queue: queue.Queue[str | None] = queue.Queue(maxsize=1024)
            reader_error: list[str] = []
            with error_path.open("w", encoding="utf-8") as stderr:
                proc = subprocess.Popen(
                    [sys.executable, "-m", "app.services.tsk_walk_isolated", "--child",
                     str(config_path), str(nodes_path)], stdout=subprocess.PIPE,
                    stderr=stderr, text=True, bufsize=1, start_new_session=True,
                )
                if on_progress:
                    on_progress(
                        f"TSK reader attempt {attempt}/{attempts} started "
                        f"(root={root_method}, inventory={inventory_mode}, pid={proc.pid}); "
                        "no partial inventory has been committed",
                        {"action": "tsk_walk_attempt_started", "reader_phase": "reopening_evidence",
                         "attempt": attempt, "reader_attempt_started_at": attempt_started,
                         "root_open_strategy": root_method, "inventory_mode": inventory_mode,
                         "reader_pid": proc.pid})
                def consume() -> None:
                    try:
                        assert proc.stdout is not None
                        for line in proc.stdout:
                            message_queue.put(line)
                    finally:
                        message_queue.put(None)

                pump = threading.Thread(target=consume, name="tsk-child-stream", daemon=True)
                pump.start()
                last_useful = time.monotonic()
                attempt_clock = last_useful
                fingerprint = None
                reader_phase = "reopening_evidence"
                last_native_call = "open_virtual_disk_from_paths"
                last_read_offset = None
                max_counts = (0, 0, 0)
                done_count = None
                next_stop_check = time.monotonic() + 10.0
                try:
                    while True:
                        now = time.monotonic()
                        # Separate zero-inventory timeout: without a single TSK
                        # entry, 420s repeated reads are wasteful. After entries
                        # begin, use the normal longer timeout for slow media.
                        timeout = root_idle if max_counts == (0, 0, 0) else idle
                        # A moving E01 offset means the root open is still reading
                        # metadata. Silence, not an active seek, is the stall.
                        offset_advancing = (
                            last_read_offset is not None and (now - last_useful) < timeout
                        )
                        if max_counts == (0, 0, 0) and now - attempt_clock >= absolute_cap:
                            raise TSKWalkTimeout(
                                f"TSK root open exceeded {int(absolute_cap)}s; "
                                f"phase={reader_phase}, last_call={last_native_call}, "
                                f"root={root_method}, attempt={attempt}/{attempts}; "
                                "read-only child will be stopped; no partial inventory committed")
                        if (
                            max_counts == (0, 0, 0)
                            and now - attempt_clock >= root_cap
                            and not offset_advancing
                        ):
                            raise TSKWalkTimeout(
                                f"TSK root open exceeded {int(root_cap)}s; "
                                f"phase={reader_phase}, last_call={last_native_call}, "
                                f"root={root_method}, attempt={attempt}/{attempts}; "
                                "read-only child will be stopped; no partial inventory committed")
                        if now - last_useful >= timeout:
                            raise TSKWalkTimeout(
                                f"TSK native reader has not advanced for {int(timeout)}s; "
                                f"phase={reader_phase}, last_call={last_native_call}, "
                                f"root={root_method}, attempt={attempt}/{attempts}; "
                                "read-only child will be stopped; no partial inventory committed")
                        if schema_name and now >= next_stop_check:
                            next_stop_check = now + 10.0
                            from app.db.session import firm_session
                            from app.services.job_control import is_stop_requested, JobStopRequested
                            with firm_session(schema_name) as control_db:
                                if is_stop_requested(control_db, vd.job_id):
                                    raise JobStopRequested("Evidence extraction stopped by examiner")
                        try:
                            line = message_queue.get(timeout=1.0)
                        except queue.Empty:
                            if proc.poll() is not None and not pump.is_alive():
                                break
                            continue
                        if line is None:
                            break
                        try:
                            event = json.loads(line)
                        except (ValueError, TypeError):
                            continue
                        if event.get("kind") == "done":
                            done_count = int(event["count"])
                            last_useful = time.monotonic()
                            continue
                        if event.get("kind") != "progress":
                            continue
                        metadata = {
                            **(event.get("metadata") or {}), "attempt": attempt,
                            "reader_attempt_started_at": attempt_started,
                            "reader_pid": proc.pid, "inventory_mode": inventory_mode,
                            "root_open_strategy": root_method,
                        }
                        counts = tuple(int(metadata.get(k) or 0) for k in (
                            "files_found", "directories_scanned", "entries_scanned"))
                        phase = str(metadata.get("reader_phase") or reader_phase)
                        action = str(metadata.get("action") or "")
                        if phase != reader_phase:
                            # A root-open milestone is meaningful native progress
                            # even if no file has been enumerated yet.
                            reader_phase = phase
                            last_useful = time.monotonic()
                        offset = metadata.get("last_source_read_offset")
                        if offset is not None and offset != last_read_offset:
                            last_read_offset = offset
                            last_useful = time.monotonic()
                        if action:
                            last_native_call = action
                        if counts > max_counts:
                            max_counts = counts
                            last_useful = time.monotonic()
                        fingerprint = (counts, reader_phase)
                        if on_progress:
                            on_progress(str(event.get("message") or "TSK walk progress"), metadata)
                    code = proc.wait(timeout=5)
                    pump.join(timeout=2)
                    if code == 0 and done_count is not None and nodes_path.exists():
                        result = []
                        with nodes_path.open("r", encoding="utf-8") as source:
                            for line in source:
                                result.append(json.loads(line))
                        if len(result) != done_count:
                            raise RuntimeError(f"TSK inventory count mismatch: read {len(result)} != {done_count}")
                        return result
                    reader_error.append(f"Isolated TSK reader exited with code {code}; "
                                        f"phase={reader_phase}, last_call={last_native_call}, "
                                        f"root={root_method}, attempt={attempt}/{attempts}")
                except Exception as exc:
                    from app.services.job_control import JobStopRequested
                    if isinstance(exc, JobStopRequested):
                        raise
                    reader_error.append(str(exc))
                finally:
                    _stop_owned_child(proc)
                    pump.join(timeout=2)
            diagnostic = error_path.read_text(encoding="utf-8", errors="replace")[-1000:]
            last_error = (TSKWalkTimeout(reader_error[-1]) if any(
                "did not advance" in item or "has not advanced" in item for item in reader_error)
                          else RuntimeError((reader_error[-1] if reader_error else "Isolated TSK reader failed")
                                            + (f"; stderr={diagnostic}" if diagnostic else "")))
            log.warning("TSK isolated inventory attempt %s/%s failed: %s", attempt, attempts, last_error)
            if on_progress:
                on_progress(f"TSK native reader attempt {attempt}/{attempts} failed: {last_error}",
                            {"action": "tsk_walk_attempt_failed", "reader_phase": "failed",
                             "attempt": attempt, "root_open_strategy": root_method,
                             "reader_attempt_started_at": attempt_started,
                             "inventory_mode": inventory_mode})
    raise last_error or RuntimeError("TSK filesystem enumeration did not complete")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "--child":
        raise SystemExit("Usage: python -m app.services.tsk_walk_isolated --child plan.json nodes.jsonl")
    raise SystemExit(_child(Path(sys.argv[2]), Path(sys.argv[3])))
