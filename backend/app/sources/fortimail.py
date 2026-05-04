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


class FortiMailSource:
    id = "fortimail"
    label = "FortiMail"
    framing: Framing = "fortinet_kv"
    pri_default = "<189>"
    os_family = "fortimail"

    def list_event_types(self) -> list[EventTypeSpec]:
        return [
            EventTypeSpec("phishing_detected", "Phishing detected", {"host_id": "string"}),
            EventTypeSpec("spam_detected", "Spam detected", {"host_id": "string"}),
            EventTypeSpec("virus_detected", "Virus detected", {"host_id": "string"}),
            EventTypeSpec("dlp_violation", "Outbound DLP violation", {"host_id": "string"}),
            EventTypeSpec("email_received", "Email received (baseline)", {"host_id": "string"}),
        ]

    def _host(self, store: InventoryStore, params: dict[str, Any]):
        hid = params.get("host_id")
        hosts = [h for h in store.list_hosts() if h.os_family == "fortimail"]
        by_id = {h.id: h for h in hosts}
        return by_id.get(hid or "") or (hosts[0] if hosts else None)

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory: InventoryStore | None = None) -> BuiltEvent:
        store = inventory or inventory_store
        h = self._host(store, params)
        if not h:
            raise ValueError("Need at least one fortimail host (os_family=fortimail)")
        reporting_ip = h.resolved_reporting_ip()
        hostname = h.hostname
        devid = f"FMVM{random.randint(100000000000, 999999999999)}"
        pri = params.get("pri", self.pri_default)

        users = store.list_users()
        frm = users[0].sam + "@corp.local" if users else "external@evil-example.com"
        to = users[1].sam + "@corp.local" if len(users) > 1 else "victim@corp.local"

        dom = next((c.domain for c in store.list_c2() if c.domain), "evil-example.com")

        if event_type == "email_received":
            subtype = "smtp"
            msg = (
                f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" eventtime={_epoch_ns()} tz="+0100" '
                f'logid="0202008451" type="event" subtype="{subtype}" level="information" vd="root" '
                f'from="{frm}" to="{to}" subject="Quarterly report" direction="incoming" '
                f'msg="Synthetic inbound mail"'
            )
        elif event_type == "phishing_detected":
            msg = (
                f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" eventtime={_epoch_ns()} tz="+0100" '
                f'logid="0200003211" type="event" subtype="phish" level="warning" vd="root" '
                f'from="attacker@{dom}" to="{to}" subject="Reset your SCADA VPN password" '
                f'action="quarantine" score=92 msg="Synthetic phishing campaign"'
            )
        elif event_type == "spam_detected":
            msg = (
                f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" eventtime={_epoch_ns()} tz="+0100" '
                f'logid="0200001203" type="event" subtype="spam" level="notice" vd="root" '
                f'from="bulk@{dom}" to="{to}" subject="Cheap OEM licenses" action="tag" score=18 '
                f'msg="Synthetic spam"'
            )
        elif event_type == "virus_detected":
            msg = (
                f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" eventtime={_epoch_ns()} tz="+0100" '
                f'logid="0200004402" type="event" subtype="virus" level="critical" vd="root" '
                f'from="{frm}" to="{to}" subject="RFQ.zip" action="blocked" virus="Malware.Generic" '
                f'msg="Synthetic malware attachment"'
            )
        elif event_type == "dlp_violation":
            msg = (
                f'date={_forti_date()} time={_forti_time()} devname="{hostname}" devid="{devid}" eventtime={_epoch_ns()} tz="+0100" '
                f'logid="0200015522" type="event" subtype="dlp" level="warning" vd="root" '
                f'from="{to}" to="personal@gmail.com" subject="SCADA drawings.zip" '
                f'policy="PII-DLP" action="blocked" msg="Synthetic outbound DLP violation"'
            )
        else:
            raise ValueError(f"Unknown fortimail event {event_type}")

        raw = f"{pri}{_bsd_ts()} {hostname} {msg}"
        return BuiltEvent(reporting_ip=reporting_ip, hostname=hostname, payload=raw, pri=str(pri), framing=self.framing)
