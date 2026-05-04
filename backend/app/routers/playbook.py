from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core import jobs as jobs_core

router = APIRouter(prefix="/api/playbook", tags=["playbook"])


class PlaybookStart(BaseModel):
    campaign_id: str = "apt_mitre"
    actors: dict[str, str | None] = Field(default_factory=dict)
    mode: str = "auto"
    step_delay: float = 0.3
    fortisiem_ip: str | None = None
    fortisiem_port: int | None = None


@router.post("/start")
def playbook_start(body: PlaybookStart):
    if body.campaign_id != "apt_mitre":
        raise HTTPException(404, detail="Unknown campaign")
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    jid = jobs_core.job_manager.spawn_playbook(
        actors=body.actors,
        mode=body.mode,
        step_delay=body.step_delay,
        fortisiem_ip=body.fortisiem_ip,
        fortisiem_port=body.fortisiem_port,
    )
    return {"job_id": jid}


@router.post("/{jid}/stop")
async def playbook_stop(jid: str):
    if job_manager is None:
        raise HTTPException(503)
    ok = await job_manager.stop(jid)
    if not ok:
        raise HTTPException(404)
    return {"ok": True}


@router.get("/{jid}")
def playbook_status(jid: str):
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    rec = jobs_core.job_manager.jobs.get(jid)
    if not rec:
        raise HTTPException(404)
    return {"id": rec.id, "kind": rec.kind, "status": rec.status, "meta": rec.meta}
