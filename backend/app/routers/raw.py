from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from app.config import settings
from app.models.common import RawSendRequest
from app.core.syslog import send_payload

router = APIRouter(prefix="/api", tags=["raw"])


def _assemble_raw(req: RawSendRequest) -> str:
    pri = req.pri or "<134>"
    ts_bsd = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    if req.framing == "rfc5424":
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        app = req.app_name or "app"
        return f"{pri}1 {ts} {req.hostname} {app} 1 {req.body}"
    # bsd / default
    suffix = f" {req.app_name}" if req.app_name else ""
    return f"{pri}{ts_bsd} {req.hostname}{suffix} {req.body}"


@router.post("/raw")
def raw_send(req: RawSendRequest, request: Request):
    history = request.app.state.history
    payload = _assemble_raw(req)
    status, _ok = send_payload(
        reporting_ip=req.reporting_ip,
        payload=payload,
        fortisiem_ip=req.fortisiem_ip or settings.fortisiem_ip,
        fortisiem_port=req.fortisiem_port or settings.fortisiem_port,
        dry_run=req.dry_run,
    )
    history.add(
        reporting_ip=req.reporting_ip,
        hostname=req.hostname,
        status=status,
        dry_run=req.dry_run,
        payload=payload,
        source_id=None,
        meta={"mode": "raw"},
    )
    return {"payload": payload, "status": status}
