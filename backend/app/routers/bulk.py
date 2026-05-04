from datetime import datetime, timezone

from fastapi import APIRouter, Request

from app.config import settings
from app.models.common import BulkSendRequest
from app.core.syslog import send_payload

router = APIRouter(prefix="/api", tags=["bulk"])


@router.post("/bulk")
def bulk_send(req: BulkSendRequest, request: Request):
    history = request.app.state.history
    dst_ip = req.fortisiem_ip or settings.fortisiem_ip
    dst_port = req.fortisiem_port or settings.fortisiem_port
    ts_bsd = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    results = []
    for line in req.lines:
        line = line.strip()
        if not line:
            continue
        if req.mode == "verbatim":
            payload = line if line.startswith("<") else f"{req.pri}{ts_bsd} host {line}"
        else:
            payload = f"{req.pri}{ts_bsd} host {line}"
        status, _ = send_payload(
            reporting_ip=req.reporting_ip,
            payload=payload,
            fortisiem_ip=dst_ip,
            fortisiem_port=dst_port,
            dry_run=req.dry_run,
        )
        history.add(
            reporting_ip=req.reporting_ip,
            hostname=None,
            status=status,
            dry_run=req.dry_run,
            payload=payload,
            source_id=None,
            meta={"mode": "bulk"},
        )
        results.append({"status": status})
    return {"count": len(results), "results": results}
