from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core import jobs as jobs_core

router = APIRouter(prefix="/api/keepalive", tags=["keepalive"])


class KeepaliveStart(BaseModel):
    interval_seconds: float = 60.0
    fortisiem_ip: str | None = None
    fortisiem_port: int | None = None


@router.post("/start")
def keepalive_start(body: KeepaliveStart):
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    jid = jobs_core.job_manager.spawn_keepalive(
        interval_seconds=body.interval_seconds,
        fortisiem_ip=body.fortisiem_ip,
        fortisiem_port=body.fortisiem_port,
    )
    return {"job_id": jid}


@router.post("/{jid}/stop")
async def keepalive_stop(jid: str):
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    ok = await jobs_core.job_manager.stop(jid)
    if not ok:
        raise HTTPException(404)
    return {"ok": True}


@router.get("/{jid}")
def keepalive_status(jid: str):
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    rec = jobs_core.job_manager.jobs.get(jid)
    if not rec:
        raise HTTPException(404)
    return {"id": rec.id, "kind": rec.kind, "status": rec.status, "meta": rec.meta}
