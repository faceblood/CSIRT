from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core import jobs as jobs_core

router = APIRouter(prefix="/api", tags=["simulate"])


class SimulatePlanItem(BaseModel):
    source_id: str
    event_types: list[str] = Field(default_factory=list)
    count: int = 1
    params: dict[str, Any] = Field(default_factory=dict)
    host_id: str | None = None


class SimulateRequest(BaseModel):
    plan: list[SimulatePlanItem]
    min_delay: float = 0.2
    max_delay: float = 0.8
    loop: bool = False
    interval_seconds: float = 60.0
    max_rounds: int = 0
    fortisiem_ip: str | None = None
    fortisiem_port: int | None = None


@router.post("/simulate")
def start_simulate(body: SimulateRequest):
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    if not body.plan:
        raise HTTPException(400, detail="plan must not be empty")
    lo, hi = body.min_delay, body.max_delay
    if hi < lo:
        lo, hi = hi, lo
    jid = jobs_core.job_manager.spawn_simulate(
        plan=[p.model_dump() for p in body.plan],
        min_delay=lo,
        max_delay=max(hi, lo),
        loop=body.loop,
        interval_seconds=body.interval_seconds,
        max_rounds=max(0, int(body.max_rounds)),
        fortisiem_ip=body.fortisiem_ip,
        fortisiem_port=body.fortisiem_port,
    )
    return {"job_id": jid}
