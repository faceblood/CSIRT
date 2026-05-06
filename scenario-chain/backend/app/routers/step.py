from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.scenario_inventory import scenario_inventory
from app.core.syslog import send_payload
from app.sources.registry import get_source

router = APIRouter(tags=["step"])


class StepBody(BaseModel):
    source_id: str
    event_type: str
    count: int = Field(ge=1, le=10_000)
    params: dict[str, Any] = Field(default_factory=dict)
    fortisiem_ip: Optional[str] = None
    fortisiem_port: Optional[int] = None
    dry_run: bool = False


@router.post("/step")
def run_step(body: StepBody):
    src = get_source(body.source_id)
    if src is None:
        raise HTTPException(status_code=404, detail=f"Unknown source_id: {body.source_id}")

    samples: list[str] = []
    sent = 0
    last_reporting = ""
    status = "noop"

    for _ in range(body.count):
        try:
            built = src.build_event(event_type=body.event_type, params=body.params, inventory=scenario_inventory)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

        last_reporting = built.reporting_ip
        status, _ok = send_payload(
            reporting_ip=built.reporting_ip,
            payload=built.payload,
            fortisiem_ip=body.fortisiem_ip,
            fortisiem_port=body.fortisiem_port,
            dry_run=body.dry_run,
        )
        sent += 1
        if len(samples) < 3:
            preview = built.payload[:500] + ("…" if len(built.payload) > 500 else "")
            samples.append(preview)

    return {
        "sent": sent,
        "samples": samples,
        "dry_run": body.dry_run,
        "status": status if body.count else "noop",
        "reporting_ip": last_reporting,
    }
