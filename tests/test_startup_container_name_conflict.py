from pathlib import Path

START = (Path(__file__).resolve().parents[1] / 'script_docker' / 'start_docker.ps1').read_text(encoding='utf-8-sig')


def test_product_start_releases_names_held_by_other_containers():
    up = START.split('function Invoke-StackUp', 1)[1].split('function Ensure-MobileCoreWorkersStarted', 1)[0]
    assert 'Remove-ForeignComposeContainerNames -Name $Name -ComposeArgs $ComposeArgs' in up
    assert "up', '-d', '--no-build'" in up
    assert 'API is healthy after the recreate' in up
    assert 'function Remove-ForeignComposeContainerNames' in START
    assert 'It is owned by' in START
    vuln = START.split('function Start-VulnerabilityStackPhased', 1)[1].split('function Get-CommonRedisState', 1)[0]
    assert "Remove-ForeignComposeContainerNames -Name 'vuln'" in vuln
