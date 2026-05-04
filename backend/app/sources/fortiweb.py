from __future__ import annotations

import random
import time
from datetime import datetime
from typing import Any

from app.sources.base import BuiltEvent, EventTypeSpec, Framing
from app.core.inventory_store import InventoryStore, inventory_store


def _forti_date() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _forti_time() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _epoch_ns() -> str:
    return f"{int(time.time())}000000000"


def _bsd_ts() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")


class FortiWebSource:
    id = "fortiweb"
    label = "FortiWeb"
    framing: Framing = "fortinet_kv"
    pri_default = "<189>"
    os_family = "fortiweb"

    def list_event_types(self) -> list[EventTypeSpec]:
        return [
            EventTypeSpec("attack_sqli", "SQL injection", {"host_id": "string"}),
            EventTypeSpec("attack_xss", "Cross-site scripting", {"host_id": "string"}),
            EventTypeSpec("attack_path_traversal", "Path traversal", {"host_id": "string"}),
            EventTypeSpec("bot_detection", "Bad bot / scanner", {"host_id": "string"}),
            EventTypeSpec("access_allow", "Access allow (baseline)", {"host_id": "string"}),
            EventTypeSpec("access_block", "Access block", {"host_id": "string"}),
        ]

    def _host(self, store: InventoryStore, params: dict[str, Any]):
        hid = params.get("host_id")
        hosts = [h for h in store.list_hosts() if h.os_family == "fortiweb"]
        if not hosts:
            hosts = [h for h in store.list_hosts() if h.role == "waf"]
        by_id = {h.id: h for h in hosts}
        return by_id.get(hid or "") or (hosts[0] if hosts else None)

    def _src(self, store: InventoryStore) -> str:
        for c in store.list_c2():
            if c.ip:
                return c.ip
        return "45.83.120.10"

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory: InventoryStore | None = None) -> BuiltEvent:
        store = inventory or inventory_store
        h = self._host(store, params)
        if not h:
            raise ValueError("Need at least one fortiweb host (os_family=fortiweb or role=waf)")
        reporting_ip = h.resolved_reporting_ip()
        hostname = h.hostname
        devid = f"FVVM{random.randint(100000000000, 999999999999)}"
        pri = params.get("pri", self.pri_default)
        src = self._src(store)

        sev = "high" if "attack" in event_type or event_type in ("access_block", "bot_detection") else "medium"
        action = "blocked" if event_type in ("attack_sqli", "attack_xss", "attack_path_traversal", "access_block", "bot_detection") else "pass"

        msg = (
            f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" '
            f'eventtime={_epoch_ns()} tz="+0100" log_id="{random.randint(20000000,29999999)}" '
            f'type="attack" subtype="waf" main_type="{event_type}" sub_type="signature" severity="{sev}" '
            f'srcip={src} srcport={random.randint(30000,65000)} dstip=10.0.10.5 dstport=443 proto=6 '
            f'method="GET" url="/api/public?id=1%27%20or%201=1--" hostname="app.example.com" '
            f'action="{action}" policy="default" msg="Synthetic FortiWeb {event_type}"'
        )
        raw = f"{pri}{_bsd_ts()} {hostname} {msg}"
        return BuiltEvent(reporting_ip=reporting_ip, hostname=hostname, payload=raw, pri=str(pri), framing=self.framing)
