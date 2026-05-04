from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from app.config import settings
from app.core.syslog import send_payload

router = APIRouter(prefix="/api", tags=["upload"])


@router.post("/upload")
async def upload_syslog_lines(
    request: Request,
    file: UploadFile = File(...),
    reporting_ip: str = Form(...),
    pri: str = Form("<134>"),
    mode: str = Form("verbatim"),
    dry_run: bool = Form(False),
    fortisiem_ip: str | None = Form(None),
    fortisiem_port: int | None = Form(None),
):
    if mode not in ("verbatim", "wrap"):
        raise HTTPException(400, detail="mode must be verbatim or wrap")
    history = request.app.state.history
    dst_ip = fortisiem_ip or settings.fortisiem_ip
    dst_port = fortisiem_port or settings.fortisiem_port
    raw = await file.read()
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(400, detail="could not decode file as UTF-8")
    lines = text.splitlines()
    ts_bsd = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if mode == "verbatim":
            payload = line if line.startswith("<") else f"{pri}{ts_bsd} host {line}"
        else:
            payload = f"{pri}{ts_bsd} host {line}"
        status, _ = send_payload(
            reporting_ip=reporting_ip,
            payload=payload,
            fortisiem_ip=dst_ip,
            fortisiem_port=dst_port,
            dry_run=dry_run,
        )
        history.add(
            reporting_ip=reporting_ip,
            hostname=None,
            status=status,
            dry_run=dry_run,
            payload=payload,
            source_id=None,
            meta={"mode": "upload", "filename": file.filename},
        )
        results.append({"status": status})
    return {"count": len(results), "results": results, "filename": file.filename}
