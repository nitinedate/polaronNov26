import ast, pathlib, time, sys, types
from unittest.mock import Mock
src=pathlib.Path(__file__).parent/'backend/app/services/progress_agent.py'
fn=next(x for x in ast.parse(src.read_text()).body if isinstance(x,ast.FunctionDef) and x.name=='queue_delivery_state')
ns={'time':time,'_QUEUE_STATE':(0,None)}
exec(compile(ast.Module(body=[fn],type_ignores=[]),str(src),'exec'),ns)
celery=types.ModuleType('celery')
app=Mock(); celery.current_app=app;sys.modules['celery']=celery
app.control.inspect.return_value.active_queues.return_value={'worker-a':[{'name':'disk-parse'}]}
app.control.inspect.return_value.active.return_value={}
assert ns['queue_delivery_state']('ocr')[0]=='blocked'
ns['_QUEUE_STATE']=(0,None)
app.control.inspect.return_value.active_queues.return_value={'worker-ocr':[{'name':'ocr'}]}
assert ns['queue_delivery_state']('ocr')[0]=='recover'
ns['_QUEUE_STATE']=(0,None)
app.control.inspect.return_value.active_queues.return_value=None
assert ns['queue_delivery_state']('ocr')[0]=='valid_wait'
print('3 queue ownership tests PASS')
