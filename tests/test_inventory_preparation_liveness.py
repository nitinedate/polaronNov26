"""Standalone regression test of classify_stage without application dependencies."""
import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

path = Path(__file__).resolve().parents[1] / 'backend/app/services/progress_agent.py'
tree = ast.parse(path.read_text())
f = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'classify_stage')
module = ast.Module(body=[f], type_ignores=[])
now = datetime.now(timezone.utc)
ns = {'datetime': datetime, 'timezone': timezone, 'CHECK_AFTER_SECONDS':60,
      'STARTUP_STALL_SECONDS':180, 'ITEM_STALL_SECONDS':90,
      'INVENTORY_PREWARM_GRACE_SECONDS':1800,
      'LIVELOCK_AFTER_DEADLINE_SECONDS':90, 'MAX_RECOVERY_ATTEMPTS':3}
def age(v, current):
    return float('inf') if not v else max(0,(current-v).total_seconds())
ns['_age'] = age
exec(compile(module,str(path),'exec'),ns)
classify=ns['classify_stage']
base={'status':'running','stage':'inventory','total_items':36,'completed_items':0,
      'failed_items':0,'skipped_items':0,'operation':'Artifact inventory: signature carving',
      'progress_at':now-timedelta(minutes=10),'heartbeat_at':now-timedelta(seconds=10)}
assert classify({},base,now=now)[0]=='valid_wait'
assert classify({}, {**base,'progress_at':now-timedelta(minutes=31)},now=now)[0]=='cancel'
assert classify({}, {**base,'heartbeat_at':now-timedelta(minutes=3)},now=now)[0]=='recover'
assert classify({}, {**base,'stage':'parse'},now=now)[0]=='cancel'
print('PASS: inventory live grace, expiration, stale heartbeat, parse unchanged')
