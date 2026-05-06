from __future__ import annotations

import random
import time
from datetime import datetime
from typing import Any, Optional

from app.core.scenario_inventory import InventoryStore, inventory_store
from app.sources.base import BuiltEvent, EventTypeSpec, Framing


def _forti_date() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _forti_time() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _epoch_ns() -> str:
    return f"{int(time.time())}000000000"


def _bsd_ts() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")


class FortiGateSource:
    id = "fortigate"
    label = "FortiGate"
    framing: Framing = "fortinet_kv"
    pri_default = "<189>"
    os_family = "fortigate"

    def list_event_types(self) -> list[EventTypeSpec]:
        return [
            EventTypeSpec("traffic_accept", "traffic accept", {"host_id": "string"}),
            EventTypeSpec("traffic_deny", "traffic deny", {"host_id": "string"}),
            EventTypeSpec("event_admin_login", "admin login event", {"host_id": "string", "user_id": "string?"}),
            EventTypeSpec("dns_query", "DNS query UTM", {"host_id": "string"}),
            EventTypeSpec("baseline_traffic", "baseline traffic", {"host_id": "string"}),
        ]

    def _host(self, store: InventoryStore, params: dict[str, Any]):
        hid = params.get("host_id")
        hosts = [h for h in store.list_hosts() if h.os_family == "fortigate"]
        by_id = {h.id: h for h in hosts}
        return by_id.get(hid or "") or (hosts[0] if hosts else None)

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory: Optional[InventoryStore] = None) -> BuiltEvent:
        store = inventory or inventory_store
        h = self._host(store, params)
        if not h:
            raise ValueError("Need at least one fortigate host in inventory")
        reporting_ip = h.resolved_reporting_ip()
        hostname = h.hostname
        devid = f"FGVM{random.randint(100000000000, 999999999999)}"
        sessionid = random.randint(100000, 999999)
        pri = params.get("pri", self.pri_default)

        dstip, dstport, service, proto = random.choice(
            [
                ("8.8.8.8", 53, "DNS", 17),
                ("1.1.1.1", 53, "DNS", 17),
                ("10.255.0.30", 443, "HTTPS", 6),
            ]
        )

        if event_type == "traffic_accept":
            msg = (
                f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" '
                f'eventtime={_epoch_ns()} tz="+0100" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
                f'srcip=10.0.10.30 srcport={random.randint(30000,65000)} srcintf="lan" srcintfrole="lan" '
                f'dstip={dstip} dstport={dstport} dstintf="wan1" dstintfrole="wan" sessionid={sessionid} '
                f'proto={proto} action="accept" policyid=1 policytype="policy" service="{service}" trandisp="noop" '
                f'sentbyte={random.randint(60,900)} rcvdbyte={random.randint(60,5000)} sentpkt={random.randint(1,12)} rcvdpkt={random.randint(1,12)} '
                f'appcat="unscanned" msg="Synthetic accept traffic"'
            )
        elif event_type == "traffic_deny":
            msg = (
                f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" '
                f'eventtime={_epoch_ns()} tz="+0100" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
                f'srcip={params.get("src_ip","10.0.10.30")} srcport={random.randint(30000,65000)} srcintf="lan" srcintfrole="lan" '
                f'dstip={params.get("dst_ip","10.255.50.10")} dstport={params.get("dst_port",502)} dstintf="lan" dstintfrole="lan" '
                f'sessionid={sessionid} proto=6 action="deny" policyid=10 policytype="policy" service="MODBUS" trandisp="noop" '
                f'sentbyte=0 rcvdbyte=0 sentpkt=1 rcvdpkt=0 appcat="unscanned" msg="Synthetic OT path denied"'
            )
        elif event_type == "event_admin_login":
            u = params.get("user") or "monitoring"
            msg = (
                f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" eventtime={_epoch_ns()} tz="+0100" '
                f'logid="0100032002" type="event" subtype="system" level="information" vd="root" logdesc="Admin login successful" '
                f'user="{u}" ui="ssh" action="login" status="success" msg="Administrator {u} logged in successfully"'
            )
        elif event_type == "dns_query":
            q = params.get("qname", "update-checkin-cdn.evil-example.com")
            msg = (
                f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" eventtime={_epoch_ns()} tz="+0100" '
                f'logid="1501054802" type="utm" subtype="dns" eventtype="dns-query" level="notice" vd="root" '
                f'srcip=10.0.10.30 srcport={random.randint(20000,65000)} dstip=8.8.8.8 dstport=53 proto=17 action="pass" '
                f'qname="{q}" qtype="A" qtypeval=1 qclass="IN" msg="Synthetic DNS query"'
            )
        elif event_type == "baseline_traffic":
            msg = (
                f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" eventtime={_epoch_ns()} tz="+0100" '
                f'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
                f'srcip=10.255.0.20 srcport={random.randint(30000,65000)} srcintf="lan" srcintfrole="lan" '
                f'dstip={dstip} dstport={dstport} dstintf="wan1" dstintfrole="wan" sessionid={sessionid} proto={proto} action="accept" '
                f'policyid=1 policytype="policy" service="{service}" trandisp="noop" sentbyte=100 rcvdbyte=200 sentpkt=2 rcvdpkt=2 '
                f'appcat="unscanned" msg="Normal keepalive traffic"'
            )
        else:
            raise ValueError(f"Unknown fortigate event {event_type}")

        raw = f"{pri}{_bsd_ts()} {hostname} {msg}"
        return BuiltEvent(reporting_ip=reporting_ip, hostname=hostname, payload=raw, pri=str(pri), framing=self.framing)
