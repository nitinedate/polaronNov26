"""Keep a directory-append lock alive from its own process.

The filesystem walk runs in native code and can hold the worker's interpreter
for longer than the lock timeout. A thread in that worker then stops updating
the lock, and another worker opens the same image. This process does not share
that interpreter.
"""

from __future__ import annotations

import json
import sys
import time


def main(schema_name: str, job_id: str, owner: str) -> None:
    from app.db.session import firm_session
    from app.db.sql_helpers import execute

    while True:
        time.sleep(20)
        payload = json.dumps({"owner": owner, "heartbeat_at": time.time()})
        try:
            with firm_session(schema_name) as db:
                execute(
                    db,
                    """UPDATE jobs
                          SET disk_source = jsonb_set(
                                COALESCE(disk_source, '{}'::jsonb),
                                '{directory_append}',
                                CAST(:payload AS jsonb),
                                true
                              ),
                              updated_at = NOW()
                        WHERE id = :id
                          AND disk_source #>> '{directory_append,owner}' = :owner""",
                    {"id": job_id, "payload": payload, "owner": owner},
                )
                db.commit()
        except Exception:
            continue


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3])
