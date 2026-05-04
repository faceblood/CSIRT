from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core import jobs as jobs_core


class JumpInjectBody(BaseModel):
    inject_idx: int = Field(ge=1, description="1-based inject index in the sorted exercise timeline")

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


def _job_or_404(jid: str):
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    rec = jobs_core.job_manager.jobs.get(jid)
    if not rec:
        raise HTTPException(404)
    return rec


@router.get("/{jid}")
def job_status(jid: str):
    rec = _job_or_404(jid)
    return {"id": rec.id, "kind": rec.kind, "status": rec.status, "meta": rec.meta}


@router.post("/{jid}/pause")
def pause_job(jid: str):
    rec = _job_or_404(jid)
    jobs_core.job_manager.pause(jid)
    return {"ok": True, "id": rec.id, "paused": True}


@router.post("/{jid}/resume")
def resume_job(jid: str):
    rec = _job_or_404(jid)
    jobs_core.job_manager.resume(jid)
    return {"ok": True, "id": rec.id, "paused": False}


@router.post("/{jid}/skip-inject")
def skip_inject(jid: str):
    rec = _job_or_404(jid)
    if rec.kind != "exercise":
        raise HTTPException(400, detail="job is not an exercise runner")
    jobs_core.job_manager.skip_exercise_inject(jid)
    return {"ok": True}


@router.post("/{jid}/jump-inject")
def jump_inject(jid: str, body: JumpInjectBody):
    rec = _job_or_404(jid)
    if rec.kind != "exercise":
        raise HTTPException(400, detail="job is not an exercise runner")
    jobs_core.job_manager.jump_exercise_to(jid, body.inject_idx)
    return {"ok": True, "inject_idx": body.inject_idx}


@router.post("/{jid}/stop")
async def stop_job(jid: str):
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    ok = await jobs_core.job_manager.stop(jid)
    if not ok:
        raise HTTPException(404)
    return {"ok": True}
