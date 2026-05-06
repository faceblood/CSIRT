from __future__ import annotations

from typing import Optional

from app.sources import fortigate as fortigate_mod
from app.sources import fortimail as fortimail_mod
from app.sources import fortiproxy as fortiproxy_mod
from app.sources import fortiweb as fortiweb_mod
from app.sources import linux as linux_mod
from app.sources import windows as windows_mod
from app.sources.base import EventSource


def all_sources() -> list[EventSource]:
    return [
        fortigate_mod.FortiGateSource(),
        linux_mod.LinuxSource(),
        windows_mod.WindowsSource(),
        fortimail_mod.FortiMailSource(),
        fortiweb_mod.FortiWebSource(),
        fortiproxy_mod.FortiProxySource(),
    ]


def get_source(source_id: str) -> Optional[EventSource]:
    for s in all_sources():
        if s.id == source_id:
            return s
    return None
