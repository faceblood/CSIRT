from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class GenerateRequest(BaseModel):
    source_id: str
    event_type: str
    params: dict[str, Any] = Field(default_factory=dict)
    count: int = 1
    dry_run: bool = False
    fortisiem_ip: str | None = None
    fortisiem_port: int | None = None


class RawSendRequest(BaseModel):
    pri: str = "<134>"
    framing: str = "bsd"
    hostname: str = "HOST"
    app_name: str | None = None
    body: str
    reporting_ip: str
    dry_run: bool = False
    fortisiem_ip: str | None = None
    fortisiem_port: int | None = None


class BulkSendRequest(BaseModel):
    lines: list[str]
    reporting_ip: str
    framing: str = "bsd"
    pri: str = "<134>"
    mode: str = Field(default="verbatim", pattern="^(verbatim|wrap)$")
    dry_run: bool = False
    fortisiem_ip: str | None = None
    fortisiem_port: int | None = None


class ActorsPayload(BaseModel):
    attacker_ip: str | None = None
    victim_linux_id: str | None = None
    victim_windows_id: str | None = None
    domain_controller_id: str | None = None
    fortigate_id: str | None = None
    fortiproxy_id: str | None = None
    fortiweb_id: str | None = None
    fortimail_id: str | None = None
    dlp_endpoint_id: str | None = None
    ot_host_id: str | None = None
    c2_id: str | None = None
    exfil_id: str | None = None
    user_id: str | None = None
