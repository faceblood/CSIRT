from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any
from uuid import uuid4


@dataclass
class HistoryEntry:
    id: str
    ts: str
    source_id: str | None
    job_id: str | None
    reporting_ip: str
    hostname: str | None
    status: str
    dry_run: bool
    payload_preview: str
    payload_full: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


class HistoryBuffer:
    def __init__(self, maxlen: int = 500):
        self._buf: deque[HistoryEntry] = deque(maxlen=maxlen)
        self._lock = Lock()

    def add(
        self,
        *,
        reporting_ip: str,
        hostname: str | None,
        status: str,
        dry_run: bool,
        payload: str,
        source_id: str | None = None,
        job_id: str | None = None,
        meta: dict[str, Any] | None = None,
        preview_len: int = 240,
    ) -> HistoryEntry:
        entry = HistoryEntry(
            id=str(uuid4()),
            ts=datetime.now(timezone.utc).isoformat(),
            source_id=source_id,
            job_id=job_id,
            reporting_ip=reporting_ip,
            hostname=hostname,
            status=status,
            dry_run=dry_run,
            payload_preview=payload[:preview_len] + ("…" if len(payload) > preview_len else ""),
            payload_full=payload if len(payload) <= 8192 else payload[:8192] + "…",
            meta=meta or {},
        )
        with self._lock:
            self._buf.appendleft(entry)
        return entry

    def list(self, *, limit: int = 200, source_id: str | None = None, job_id: str | None = None):
        with self._lock:
            rows = list(self._buf)
        out = rows
        if source_id:
            out = [r for r in out if r.source_id == source_id]
        if job_id:
            out = [r for r in out if r.job_id == job_id]
        return out[:limit]
