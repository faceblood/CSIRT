from __future__ import annotations

from typing import TYPE_CHECKING

from app.sources import fortiedr as fortiedr_mod
from app.sources import fortigate as fortigate_mod
from app.sources import fortidlp as fortidlp_mod
from app.sources import fortimail as fortimail_mod
from app.sources import fortiproxy as fortiproxy_mod
from app.sources import fortiweb as fortiweb_mod
from app.sources import linux as linux_mod
from app.sources import windows as windows_mod
from app.sources.activedirectory import ActiveDirectorySource

if TYPE_CHECKING:
    from app.sources.base import EventSource


def all_sources() -> list[EventSource]:
    return [
        fortiedr_mod.FortiEdrSource(),
        windows_mod.WindowsSource(),
        ActiveDirectorySource(),
        linux_mod.LinuxSource(),
        fortigate_mod.FortiGateSource(),
        fortiproxy_mod.FortiProxySource(),
        fortiweb_mod.FortiWebSource(),
        fortimail_mod.FortiMailSource(),
        fortidlp_mod.FortiDlpSource(),
    ]


def get_source(source_id: str) -> EventSource:
    for s in all_sources():
        if s.id == source_id:
            return s
    raise KeyError(source_id)
