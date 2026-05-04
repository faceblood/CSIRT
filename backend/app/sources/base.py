from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol


Framing = Literal["rfc5424", "bsd", "mswineventlog", "fortinet_kv", "cef"]


@dataclass
class EventTypeSpec:
    id: str
    label: str
    schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class BuiltEvent:
    reporting_ip: str
    hostname: str
    payload: str
    pri: str
    framing: Framing


class EventSource(Protocol):
    id: str
    label: str
    framing: Framing
    pri_default: str
    os_family: str | None

    def list_event_types(self) -> list[EventTypeSpec]: ...

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory) -> BuiltEvent: ...
