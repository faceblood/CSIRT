from __future__ import annotations

from pydantic import BaseModel, Field


class HostRow(BaseModel):
    id: str | None = None
    hostname: str
    ip: str
    os: str = ""
    os_family: str = "linux"
    role: str = ""
    reporting_ip: str | None = None
    group: str = ""

    def resolved_reporting_ip(self) -> str:
        return self.reporting_ip or self.ip


class UserRow(BaseModel):
    id: str | None = None
    domain: str = "corp"
    sam: str
    upn: str | None = None
    sid: str | None = None
    role: str | None = None


class C2Row(BaseModel):
    id: str | None = None
    ip: str = ""
    domain: str = ""
    country: str = "N/A"
    asn: str = "N/A"
    role: str = Field(default="c2", description="c2 | exfil | staging | external | attacker")
