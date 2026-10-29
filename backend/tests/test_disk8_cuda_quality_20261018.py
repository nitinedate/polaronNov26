"""Regression tests for the eight-slot forensic + independent CUDA lane plan.

Run without forensic image or live DB; source checks do not claim E01 speed.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
from types import SimpleNamespace

from app.services.host_capacity import HostSnapshot, build_capacity_plan
from app.services.extract_filters import should_extract_node


APP = Path(__file__).resolve().parents[1] / 'app'


def _source_function(path: Path, name: str, names: dict):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    methods = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(methods) == 1
    exec(compile(ast.Module(body=methods, type_ignores=[]), str(path), 'exec'), names)
    return names[name]


def _gpu_host():
    return HostSnapshot(cpu_logical=16, mem_total_mb=64000, mem_available_mb=38000,
                        gpu_available=True, gpu_name='CUDA test card',
                        gpu_vram_total_mb=12288, gpu_vram_free_mb=10000,
                        gpu_temp_c=50, cpu_temp_c=55, load_1m=1.0, profile='laptop')


def test_gpu_host_keeps_vector_quality_and_eight_cpu_slots(monkeypatch):
    monkeypatch.delenv('RAG_EMBEDDING_ENABLED', raising=False)
    p = build_capacity_plan(_gpu_host())
    assert p.env['RAG_EMBEDDING_ENABLED'] == 'true'
    assert p.env['RAG_EMBEDDING_DEVICE'] == 'cuda'
    assert p.env['OCR_DEVICE'] == 'cuda'
    assert int(p.env['EXTRACT_DISK_WORKERS']) <= 8
    assert int(p.env['PARSE_WORKERS']) <= 8
    assert int(p.env['GPU_HEAVY_MAX_CONCURRENT']) in (1, 2)
    assert p.env['EXTRACT_THEN_PROCESS'] == 'true'


def test_gpu_embedding_opt_out_is_respected(monkeypatch):
    monkeypatch.setenv('RAG_EMBEDDING_ENABLED', 'false')
    assert build_capacity_plan(_gpu_host()).env['RAG_EMBEDDING_ENABLED'] == 'false'
    monkeypatch.setenv('RAG_EMBEDDING_ENABLED', 'true')
    assert build_capacity_plan(_gpu_host()).env['RAG_EMBEDDING_ENABLED'] == 'true'


def test_single_ewf_job_caps_at_eight_readers():
    planner = _source_function(APP/'services'/'extracted_disk.py', 'plan_ewf_extract_io',
                               {'os':os})
    readers, shards, reason = planner(
        [{'path':f'f{i}', 'inode':i} for i in range(5000)], configured_workers=18,
        configured_shards=16, live_workers=18, cpu_count=32)
    assert readers == 8
    assert shards >= readers
    assert reason.startswith('ewf_parallel')


def test_full_mode_cannot_drop_large_source_for_generic_fast_cap():
    for path in ('Users/Employee/Documents/five_gig_archive.pst',
                 'Users/Employee/Documents/acquisition.vhdx'):
        include, reason = should_extract_node(
            path, 5 * 1024**3, mode='full', max_file_bytes=100_000_000,
            skip_system_paths=False, os_family='windows')
        assert (include,reason) == (True,None)


def test_forensic_mode_still_respects_configured_size_cap():
    include, reason = should_extract_node(
        'Users/Employee/Documents/big.pst', 5*1024**3, mode='forensic',
        max_file_bytes=100_000_000, skip_system_paths=False,
        os_family='windows')
    assert (include,reason) == (False,'too_large')


def test_retrieval_uses_vectors_only_when_indexed_setting_enabled():
    fn = _source_function(APP/'retrieval'/'hybrid.py', 'settings_want_vector',
                          {'get_settings':lambda: SimpleNamespace(rag_embedding_enabled=True)})
    assert fn() is True
    fn = _source_function(APP/'retrieval'/'hybrid.py', 'settings_want_vector',
                          {'get_settings':lambda: SimpleNamespace(rag_embedding_enabled=False)})
    assert fn() is False
