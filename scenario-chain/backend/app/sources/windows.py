from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

from app.core.scenario_inventory import InventoryStore, inventory_store
from app.sources.base import BuiltEvent, EventTypeSpec, Framing


def _load_windows_module():
    path = Path(__file__).resolve().parent.parent / "vendor" / "windows_spoofed_events_fortisiem_modern_aligned.py"
    spec = importlib.util.spec_from_file_location("win_spoof", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class WindowsSource:
    id = "windows"
    label = "Windows (Security + Sysmon)"
    framing: Framing = "mswineventlog"
    pri_default = "<134>"
    os_family = "windows"

    def __init__(self) -> None:
        self._mod = None

    @property
    def mod(self):
        if self._mod is None:
            self._mod = _load_windows_module()
        return self._mod

    def list_event_types(self) -> list[EventTypeSpec]:
        return [
            EventTypeSpec("4625", "4625 Failed logon", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("4624", "4624 Successful logon", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("4688", "4688 Process created", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("1102", "1102 Audit cleared", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("7045", "7045 Service installed", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("sysmon_1", "Sysmon 1 Process Create", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("sysmon_3", "Sysmon 3 Network connection", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("sysmon_11", "Sysmon 11 File created", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("sysmon_22", "Sysmon 22 DNS query", {"host_id": "string", "user_id": "string"}),
        ]

    def _resolve(self, store: InventoryStore, params: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
        hid = params.get("host_id") or params.get("victim_windows_id")
        uid = params.get("user_id") or params.get("user")
        hosts = {h.id: h for h in store.list_hosts() if h.os_family == "windows" and h.role != "domain_controller"}
        users = {u.id: u for u in store.list_users()}
        h = hosts.get(hid or "") or next(iter(hosts.values()), None)
        u = users.get(uid or "") or next(iter(users.values()), None)
        if not h or not u:
            raise ValueError("Need at least one windows host and one user in inventory")
        domain = u.domain.upper() if u.domain else "CORP"
        attacker = next((c.ip for c in store.list_c2() if c.role == "attacker" and c.ip), "185.231.88.45")
        return h.resolved_reporting_ip(), h.hostname, h.ip, domain, u.sam, attacker

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory: Optional[InventoryStore] = None) -> BuiltEvent:
        store = inventory or inventory_store
        reporting_ip, hostname, windows_ip, domain, user, attacker_ip = self._resolve(store, params)
        m = self.mod
        args = SimpleNamespace(
            fortisiem_ip="",
            port=514,
            reporting_ip=reporting_ip,
            hostname=hostname,
            windows_ip=windows_ip,
            domain=domain,
            user=user,
            attacker_ip=attacker_ip,
            pri=self.pri_default,
        )
        builders = {
            "4625": m.event_4625_failed_logon,
            "4624": m.event_4624_success_logon,
            "4688": m.event_4688_process_created,
            "1102": m.event_1102_audit_cleared,
            "7045": m.event_7045_service_installed,
            "sysmon_1": m.event_sysmon_1,
            "sysmon_3": m.event_sysmon_3,
            "sysmon_11": m.event_sysmon_11,
            "sysmon_22": m.event_sysmon_22,
        }
        fn = builders.get(event_type)
        if fn is None:
            raise ValueError(f"Unknown windows event_type {event_type}")
        payload_body = fn(args)
        raw = f"{args.pri}{m.syslog_ts()} {args.hostname} {payload_body}"
        return BuiltEvent(reporting_ip=reporting_ip, hostname=hostname, payload=raw, pri=args.pri, framing=self.framing)
