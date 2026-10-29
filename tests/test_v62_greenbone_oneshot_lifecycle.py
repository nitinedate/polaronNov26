from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PS = (ROOT / 'script_docker' / 'start_docker.ps1').read_text(encoding='utf-8-sig')


def test_feed_runner_does_not_use_compose_rm():
    block = PS[PS.index('function Invoke-VulnOneShot'):PS.index('function Start-VulnerabilityStackPhased')]
    assert "'rm','-sf'" not in block
    assert 'Remove-ComposeOneShotContainer' in block


def test_native_docker_progress_is_not_fatal():
    assert 'function Invoke-DockerNativeSafe' in PS
    assert "$ErrorActionPreference = 'Continue'" in PS
    assert '2>&1' in PS
    assert 'return [int]$LASTEXITCODE' in PS


def test_stale_container_removed_by_id_and_waited_out():
    assert 'function Remove-ComposeOneShotContainer' in PS
    assert "@('update','--restart=no',$cid)" in PS
    assert "@('rm','-f',$cid)" in PS
    assert 'Start-Sleep -Milliseconds 500' in PS


def test_feed_success_uses_final_native_exit_code():
    block = PS[PS.index('function Invoke-VulnOneShot'):PS.index('function Start-VulnerabilityStackPhased')]
    assert '$exitCode = Invoke-DockerNativeSafe' in block
    assert 'if ($exitCode -eq 0)' in block
    assert 'returned exit code $exitCode' in block
