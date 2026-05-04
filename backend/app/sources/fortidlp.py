from __future__ import annotations

import random
from datetime import datetime
from typing import Any

from app.sources.base import BuiltEvent, EventTypeSpec, Framing
from app.core.inventory_store import InventoryStore, inventory_store


def _cef_ts() -> str:
    return datetime.utcnow().strftime("%b %d %Y %H:%M:%S")


class FortiDlpSource:
    id = "fortidlp"
    label = "FortiDLP"
    framing: Framing = "cef"
    pri_default = "<134>"
    os_family = None  # endpoint agent on windows/linux

    def list_event_types(self) -> list[EventTypeSpec]:
        return [
            EventTypeSpec("cloud_upload", "Cloud upload exfil", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("usb_write", "USB write", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("pii_detected", "PII detected", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("policy_match", "Policy match (baseline)", {"host_id": "string", "user_id": "string"}),
        ]

    def _host(self, store: InventoryStore, params: dict[str, Any]):
        hid = params.get("host_id") or params.get("dlp_endpoint_id")
        hosts = [h for h in store.list_hosts() if h.os_family in ("windows", "linux")]
        by_id = {h.id: h for h in hosts}
        return by_id.get(hid or "") or (hosts[0] if hosts else None)

    def _user(self, store: InventoryStore, params: dict[str, Any]) -> str:
        uid = params.get("user_id")
        users = store.list_users()
        by_id = {u.id: u for u in users}
        u = by_id.get(uid or "") or (users[0] if users else None)
        return u.sam if u else "user"

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory: InventoryStore | None = None) -> BuiltEvent:
        store = inventory or inventory_store
        h = self._host(store, params)
        if not h:
            raise ValueError("Need at least one windows/linux host for FortiDLP")
        reporting_ip = h.resolved_reporting_ip()
        hostname = h.hostname
        user = self._user(store, params)
        domain = next((u.domain for u in store.list_users() if u.sam == user), "corp")
        dst = next((c.domain for c in store.list_c2() if c.role in ("exfil", "c2") and c.domain), "upload.example.com")

        sev = 8 if event_type in ("cloud_upload", "usb_write") else 5
        channel = {"cloud_upload": "Cloud", "usb_write": "USB", "pii_detected": "Endpoint", "policy_match": "Endpoint"}.get(
            event_type, "Endpoint"
        )
        fname = params.get("fname", "C:\\\\Shares\\\\Finance\\\\ledger.xlsx")

        ext = (
            f"suser={domain}\\\\{user} shost={hostname} src={reporting_ip} "
            f"act={'blocked' if event_type != 'policy_match' else 'detected'} "
            f"fname={fname} fsize={random.randint(10000,500000)} outcome={'blocked' if sev>=8 else 'observed'} "
            f"cs1Label=Policy cs1=Finance-Strict cs2Label=Channel cs2={channel} "
            f'msg="Synthetic FortiDLP {event_type}"'
        )

        cef = (
            f"CEF:0|Fortinet|FortiDLP|1.0|{random.randint(1000,9999)}|{event_type}|{sev}|{ext}"
        )
        pri = params.get("pri", self.pri_default)
        raw = f"{pri}{datetime.now().strftime('%b %d %H:%M:%S')} {hostname} {cef}"
        return BuiltEvent(reporting_ip=reporting_ip, hostname=hostname, payload=raw, pri=str(pri), framing=self.framing)
