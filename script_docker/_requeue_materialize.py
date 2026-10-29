from sqlalchemy import text
from app.db.session import SessionLocal
from app.tasks import phase3_pipeline_task

JOB = "abf989c4-83c4-4bc3-af1d-5c617410b6d9"
db = SessionLocal()
db.execute(text("SET search_path TO firm_p, public"))
db.execute(
    text(
        """UPDATE pipeline_stage_runs
           SET status='pending', error=NULL, updated_at=NOW()
           WHERE job_id=:id AND status='failed'"""
    ),
    {"id": JOB},
)
db.execute(
    text("UPDATE jobs SET status='indexing', error=NULL, updated_at=NOW() WHERE id=:id"),
    {"id": JOB},
)
db.commit()
print(phase3_pipeline_task.delay("firm_p", JOB).id)
