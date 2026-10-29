"""Examiner review of the extraction plan (choose folders to leave out before reading)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.deps import CurrentUser, firm_db, require_firm_permission

router = APIRouter(prefix="/api", tags=["extract-review"])

_ACTIVE = {"processing", "building_disk", "extracting", "parsing", "indexing", "ocr", "ocring"}


class ReviewSettingsBody(BaseModel):
    required: bool


class ReviewDecisionBody(BaseModel):
    excluded_paths: list[str] = Field(default_factory=list, max_length=1000)


def _error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})


@router.get("/jobs/{job_id}/extract-review")
def get_review(job_id: str, db: Session = Depends(firm_db),
               current: CurrentUser = Depends(require_firm_permission("job:read"))):
    from app.routers.jobs import _ensure_job
    from app.services import extract_review
    from app.services.known_good_filter import status as known_good_status

    _ensure_job(db, job_id)
    st = extract_review.state(extract_review._load_ds(db, job_id))
    return {**st, "required": bool(st.get("required")), "known_good": known_good_status()}


@router.put("/jobs/{job_id}/extract-review/settings")
def set_review_required(job_id: str, body: ReviewSettingsBody, db: Session = Depends(firm_db),
                        current: CurrentUser = Depends(require_firm_permission("job:run"))):
    from app.routers.jobs import _ensure_job
    from app.services import extract_review

    row = _ensure_job(db, job_id)
    ds = extract_review._load_ds(db, job_id)
    st = extract_review.state(ds)
    if st.get("status") == "pending" and not body.required:
        raise _error(409, "review_pending", "A review is waiting: continue it instead of switching it off")
    if (row.get("status") or "") in _ACTIVE and body.required != bool(st.get("required")):
        raise _error(409, "job_running", "The extraction is already running")
    st["required"] = body.required
    ds[extract_review.REVIEW_KEY] = st
    extract_review._save_ds(db, job_id, ds)
    db.commit()
    return {"ok": True, "required": body.required}


@router.post("/jobs/{job_id}/extract-review")
def submit_review(job_id: str, body: ReviewDecisionBody, db: Session = Depends(firm_db),
                  current: CurrentUser = Depends(require_firm_permission("job:run"))):
    from app.routers.jobs import _ensure_job, resume_job
    from app.services import extract_review
    from app.services.disk_build_log import write_disk_log

    _ensure_job(db, job_id)
    ds = extract_review._load_ds(db, job_id)
    st = extract_review.state(ds)
    if st.get("status") != "pending":
        raise _error(409, "review_not_pending", "This job is not waiting for an extraction review")
    try:
        excluded = extract_review.clean_exclusions(body.excluded_paths)
    except ValueError as exc:
        raise _error(400, "too_many_exclusions", str(exc))
    summary = st.get("summary") or {}
    # Estimated bytes left out, from the summary (top-level choices only, no double counting).
    keys = sorted({p.lower() for p in excluded})
    roots = [k for k in keys if not any(k != o and k.startswith(o + "/") for o in keys)]
    sizes = {f["path"].lower(): int(f["bytes"]) for f in summary.get("folders") or []}
    sizes.update({f["path"].lower(): int(f["bytes"]) for f in summary.get("big_files") or []})
    estimate = sum(sizes.get(r, 0) for r in roots)
    st.update({
        "status": "approved",
        "excluded": excluded,
        "excluded_estimate_bytes": estimate,
        "decided_by": getattr(current, "email", "") or "",
        "decided_at": datetime.now(timezone.utc).isoformat(),
    })
    ds[extract_review.REVIEW_KEY] = st
    extract_review._save_ds(db, job_id, ds)
    write_disk_log(
        db, job_id,
        (f"Examiner review completed by {st['decided_by'] or 'examiner'} — "
         + (f"{len(excluded)} path(s) left out (about {extract_review._human(estimate)}): "
            + "; ".join(excluded[:10]) + (" …" if len(excluded) > 10 else "")
            if excluded else "nothing left out")
         + ". Named artifacts inside excluded folders are still extracted."),
        stage="extract", metadata={"examiner_review": "approved", "excluded": excluded,
                                   "excluded_estimate_bytes": estimate},
    )
    db.commit()
    resumed = resume_job(job_id, db=db, current=current)
    return {"ok": True, "excluded": excluded, "excluded_estimate_bytes": estimate, "resume": resumed}
