from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = (ROOT / 'script_docker' / 'start_docker.lib.ps1').read_text(encoding='utf-8-sig')
START = (ROOT / 'script_docker' / 'start_docker.ps1').read_text(encoding='utf-8-sig')


def test_created_and_restarting_are_pending_not_failed():
    assert 'if ($status -in @(\"created\", \"restarting\", \"removing\")) { $pending++; continue }' in LIB


def test_mobile_core_worker_reconcile_exists():
    assert 'function Ensure-MobileCoreWorkersStarted' in START
    assert "@('worker-build','worker-parse')" in START
    assert "Wait-ComposeServiceReady -ProjectName $projectName -Service 'api'" in START
    assert "Wait-ComposeServiceReady -ProjectName $projectName -Service 'nvidia-cuda'" in START


def test_mobile_stacks_reconcile_after_up():
    marker = 'Invoke-StackUp -Name $name -ComposeArgs $args\n        Ensure-MobileCoreWorkersStarted -Name $name -ComposeArgs $args'
    assert marker in START


def test_created_worker_is_restarted_via_compose_not_docker_start():
    assert "$state.Status -eq 'created'" in START
    assert "@('up','-d','--no-build','--pull','missing',$service)" in START
