"""Mount client-workstation evidence before any job task runs in a worker container.

Every Aetheris task takes ``(schema_name, job_id, …)``.  Before the task body
executes, the shares registered for that job are mounted in this container, so
extraction/parse/OCR code opens ``/client-evidence/<share>/…`` exactly like a
server drive path.  Jobs without client evidence cost one Redis SMEMBERS call.
"""

from __future__ import annotations

import logging
import re

log = logging.getLogger(__name__)

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SKIP_TASKS = {
    "app.tasks.progress_agent_task",
    "app.tasks.forensic_failure_email_task",
}
_installed = False


def _job_id_from(args, kwargs) -> str | None:
    if isinstance(kwargs, dict):
        value = kwargs.get("job_id")
        if isinstance(value, str) and _UUID_RE.match(value):
            return value
    if isinstance(args, (list, tuple)):
        for value in args[:3]:
            if isinstance(value, str) and _UUID_RE.match(value):
                return value
    return None


def _on_task_prerun(sender=None, task_id=None, task=None, args=None, kwargs=None, **_extra):
    try:
        from app.services.client_evidence import enabled

        if not enabled():
            return
        name = getattr(task, "name", "") or getattr(sender, "name", "")
        if name in _SKIP_TASKS:
            return
        job_id = _job_id_from(args, kwargs)
        if not job_id:
            return
        from app.services.client_evidence.mount import ensure_job_mounts

        ensure_job_mounts(job_id)
    except Exception as exc:  # never block a task because of this hook
        log.warning("client evidence prerun hook failed: %s", exc)


def install_celery_hooks() -> None:
    global _installed
    if _installed:
        return
    from celery.signals import task_prerun

    task_prerun.connect(_on_task_prerun, weak=False)
    _installed = True
