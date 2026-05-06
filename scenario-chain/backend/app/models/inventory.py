from typing import Optional

from pydantic import BaseModel, Field


class HostRow(BaseModel):
    id: Optional[str] = None
    hostname: str
    ip: str
    os: str = ""
    os_family: str = "linux"
    role: str = ""
    reporting_ip: Optional[str] = None
    group: str = ""

    def resolved_reporting_ip(self) -> str:
        return self.reporting_ip or self.ip


class UserRow(BaseModel):
    id: Optional[str] = None
    domain: str = "corp"
    sam: str
    upn: Optional[str] = None
    sid: Optional[str] = None
    role: Optional[str] = None


class C2Row(BaseModel):
    id: Optional[str] = None
    ip: str = ""
    domain: str = ""
    country: str = "N/A"
    asn: str = "N/A"
    role: str = Field(default="c2", description="c2 | exfil | staging | external | attacker")
