from fastapi import APIRouter, HTTPException, Request

from app.config import settings
from app.models.common import GenerateRequest
from app.core.syslog import send_payload
from app.sources.registry import get_source

router = APIRouter(prefix="/api", tags=["generate"])


@router.post("/generate")
def generate(req: GenerateRequest, request: Request):
    history = request.app.state.history
    try:
        src = get_source(req.source_id)
    except KeyError:
        raise HTTPException(404, detail=f"Unknown source {req.source_id}")

    fortisiem_ip = req.fortisiem_ip or settings.fortisiem_ip
    fortisiem_port = req.fortisiem_port or settings.fortisiem_port
    results = []
    for _ in range(max(1, req.count)):
        built = src.build_event(event_type=req.event_type, params=req.params)
        status, ok = send_payload(
            reporting_ip=built.reporting_ip,
            payload=built.payload,
            fortisiem_ip=fortisiem_ip,
            fortisiem_port=fortisiem_port,
            dry_run=req.dry_run,
        )
        history.add(
            reporting_ip=built.reporting_ip,
            hostname=built.hostname,
            status=status,
            dry_run=req.dry_run,
            payload=built.payload,
            source_id=req.source_id,
            meta={"event_type": req.event_type},
        )
        results.append({"payload": built.payload, "reporting_ip": built.reporting_ip, "hostname": built.hostname, "status": status})
    return {"results": results}
