"""Disk/Mobile policy: dependency-safe stages with eight independent evidence units."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from contextlib import contextmanager
from contextvars import ContextVar
import multiprocessing
import os

from app.services.disk_slots import DISK_SLOTS, run_bounded

# CPU-bound helpers stay within the host. Disk shard and parse work uses DISK_SLOTS
# (eight) instead, because those waits are storage waits.
_CPU_COUNT = max(int(os.cpu_count() or 4), 1)
MAX_PARALLELISM = max(2, min(int(os.environ.get("FORENSIC_MAX_PARALLELISM", min(8, _CPU_COUNT)) or 8), 8))
PIPELINE_PARALLEL_SLOTS = max(2, min(int(os.environ.get("PIPELINE_PARALLEL_SLOTS", "8") or 8), 8))
# Character windows for complete forensic evidence, including any source header.
CHUNK_SIZE = 3000
CHUNK_OVERLAP = 800
CHUNK_POLICY = "chars-3000-overlap-800-v3"
# A finished file keeps its previous window. A size change must not rechunk it.
ACCEPTED_CHUNK_POLICIES = (CHUNK_POLICY, "chars-2500-overlap-800-v2")
_stage_context: ContextVar[str | None] = ContextVar(
    "forensic_serial_stage", default=None
)


def serial_enabled() -> bool:
    # This policy is deliberately unrelated to PERF_POLICY_MODE or the scanner.
    from app.service_identity import VULN, current_service

    return current_service() != VULN


def parallelism(requested: int = MAX_PARALLELISM) -> int:
    return max(1, min(MAX_PARALLELISM, int(requested or 1)))


def chunk_policy_accepted_sql(expr: str = "COALESCE(metadata->>'serial_chunk_policy','')") -> str:
    values = ",".join(f"'{policy}'" for policy in ACCEPTED_CHUNK_POLICIES)
    return f"{expr} IN ({values})"


def current_stage() -> str | None:
    return _stage_context.get()


@contextmanager
def stage_context(stage: str):
    token = _stage_context.set(stage)
    try:
        yield
    finally:
        _stage_context.reset(token)


def bounded_map(fn, items, *, workers: int = MAX_PARALLELISM):
    """Run evidence units through the disk semaphore. No thread-pool executor.

    Database Sessions must be created inside fn, never shared across these threads.
    """
    # Disk stages admit eight slots even when the host CPU cap is lower.
    # The work is storage-bound. OCR and other CPU helpers keep parallelism().
    slots = max(1, min(int(workers or 1), DISK_SLOTS))
    yield from run_bounded(fn, items, slots=slots)


def bounded_process_map(fn, items, *, workers: int = MAX_PARALLELISM):
    """Parallelize pure CPU work without sharing DB sessions or CUDA contexts.

    Stage workers are normal subprocesses and can use a spawn process pool. If a
    caller is ever executed from a daemonic process, fall back to threads rather
    than failing with "daemonic processes are not allowed to have children".
    Inputs and outputs must be picklable and database access must stay outside fn.
    """
    slots = min(parallelism(workers), DISK_SLOTS)
    if multiprocessing.current_process().daemon:
        # A daemonic worker cannot spawn processes. Use the same eight slots.
        yield from run_bounded(fn, items, slots=slots)
        return
    source = iter(items)
    kwargs = {"max_workers": slots, "mp_context": multiprocessing.get_context("spawn")}
    with ProcessPoolExecutor(**kwargs) as pool:
        pending = set()
        exhausted = False
        while pending or not exhausted:
            while len(pending) < slots and not exhausted:
                try:
                    pending.add(pool.submit(fn, next(source)))
                except StopIteration:
                    exhausted = True
            if not pending:
                break
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                yield future.result()


def shard_overlap_enabled() -> bool:
    """Opt-in until verified against real extraction and PostgreSQL integration."""
    return os.environ.get("FORENSIC_STREAM_SHARD_OVERLAP", "false").strip().lower() in {"1", "true", "yes"}
