from __future__ import annotations

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("")
def history(request: Request, limit: int = Query(200, ge=1, le=500), source_id: str | None = None, job_id: str | None = None):
    rows = request.app.state.history.list(limit=limit, source_id=source_id, job_id=job_id)
    return [
        {
            "id": r.id,
            "ts": r.ts,
            "source_id": r.source_id,
            "job_id": r.job_id,
            "reporting_ip": r.reporting_ip,
            "hostname": r.hostname,
            "status": r.status,
            "dry_run": r.dry_run,
            "payload_preview": r.payload_preview,
            "meta": r.meta,
        }
        for r in rows
    ]
