from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "script_docker" / "start_docker.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8-sig")


def test_crash_loop_cleanup_force_removes_redis_container():
    assert "function Remove-CommonRedisContainerForRepair" in TEXT
    assert "docker update --restart=no" in TEXT
    assert "docker rm -f" in TEXT


def test_repair_does_not_use_compose_stop_on_crash_looping_redis():
    start = TEXT.index("function Repair-CommonRedis")
    end = TEXT.index("function Ensure-CommonRedisHealthy", start)
    block = TEXT[start:end]
    assert "@('stop', 'redis')" not in block
    assert "Remove-CommonRedisContainerForRepair -ContainerId $state.Id" in block


def test_backup_is_taken_before_live_volume_repair():
    start = TEXT.index("function Repair-CommonRedis")
    end = TEXT.index("function Ensure-CommonRedisHealthy", start)
    block = TEXT[start:end]
    assert block.index("Backup-RedisVolume") < block.index("Remove-CommonRedisContainerForRepair -ContainerId $state.Id")
    assert block.index("Backup-RedisVolume") < block.index("redis-check-aof --fix")


def test_failed_restart_is_removed_before_quarantine():
    start = TEXT.index("function Repair-CommonRedis")
    end = TEXT.index("function Ensure-CommonRedisHealthy", start)
    block = TEXT[start:end]
    assert "$failedRestart = Get-CommonRedisState" in block
    assert "Remove-CommonRedisContainerForRepair -ContainerId $failedRestart.Id" in block
    assert block.index("Remove-CommonRedisContainerForRepair -ContainerId $failedRestart.Id") < block.index("$quarantineScript = @'")


def test_redis7_multipart_aof_repair_is_retained():
    assert "/data/appendonlydir/appendonly.aof.manifest" in TEXT
    assert "redis-check-aof --fix /data/appendonlydir/appendonly.aof.manifest" in TEXT


def test_https_guidance_is_not_reported_as_universal_root_cause():
    assert "If the error above is HTTPS-related" in TEXT
    assert "If the error names Redis/Postgres/MinIO" in TEXT
