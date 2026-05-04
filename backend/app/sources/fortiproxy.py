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


class FortiProxySource:
    id = "fortiproxy"
    label = "FortiProxy"
    framing: Framing = "fortinet_kv"
    pri_default = "<189>"
    os_family = "fortiproxy"

    def list_event_types(self) -> list[EventTypeSpec]:
        return [
            EventTypeSpec("webfilter_passthrough", "webfilter passthrough", {"host_id": "string", "user_id": "string?"}),
            EventTypeSpec("webfilter_block", "webfilter block", {"host_id": "string", "user_id": "string?"}),
            EventTypeSpec("baseline_webfilter", "baseline webfilter", {"host_id": "string"}),
        ]

    def _host(self, store: InventoryStore, params: dict[str, Any]):
        hid = params.get("host_id")
        hosts = [h for h in store.list_hosts() if h.os_family == "fortiproxy"]
        by_id = {h.id: h for h in hosts}
        return by_id.get(hid or "") or (hosts[0] if hosts else None)

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory: InventoryStore | None = None) -> BuiltEvent:
        store = inventory or inventory_store
        h = self._host(store, params)
        if not h:
            raise ValueError("Need at least one fortiproxy host in inventory")
        reporting_ip = h.resolved_reporting_ip()
        hostname = h.hostname
        devid = f"FPXVM{random.randint(100000000000, 999999999999)}"
        pri = params.get("pri", self.pri_default)
        user = "monitoring"
        uid = params.get("user_id")
        if uid:
            u = next((x for x in store.list_users() if x.id == uid), None)
            if u:
                user = u.sam

        url, hosth, dstip, dstport, service = random.choice(
            [
                ("http://connectivity-check.ubuntu.com/", "connectivity-check.ubuntu.com", "91.189.91.48", 80, "HTTP"),
                ("http://example.com/healthcheck", "example.com", "93.184.216.34", 80, "HTTP"),
                ("https://repo.example.com/status", "repo.example.com", "93.184.216.34", 443, "HTTPS"),
            ]
        )
        action = "passthrough"
        level = "notice"
        if event_type == "webfilter_block":
            action = "blocked"
            level = "warning"
        if event_type == "baseline_webfilter":
            action = "passthrough"

        msg = (
            f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" '
            f'eventtime={_epoch_ns()} tz="+0100" logid="0317013312" type="utm" subtype="webfilter" '
            f'eventtype="urlfilter" level="{level}" vd="root" policyid=10 sessionid={random.randint(300000,399999)} '
            f'user="{user}" srcip=10.0.10.30 srcport={random.randint(30000,65000)} dstip={dstip} dstport={dstport} '
            f'proto=6 service="{service}" hostname="{hosth}" profile="default" action="{action}" reqtype="direct" '
            f'url="{url}" sentbyte={random.randint(200,1200)} rcvdbyte={random.randint(1000,7000)} '
            f'direction="outgoing" msg="Synthetic proxy webfilter"'
        )
        raw = f"{pri}{_bsd_ts()} {hostname} {msg}"
        return BuiltEvent(reporting_ip=reporting_ip, hostname=hostname, payload=raw, pri=str(pri), framing=self.framing)
