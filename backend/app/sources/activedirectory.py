from __future__ import annotations

import random
from datetime import datetime
from typing import Any

from app.sources.base import BuiltEvent, EventTypeSpec, Framing
from app.core.inventory_store import InventoryStore, inventory_store


def _syslog_ts() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")


def _win_time_parts() -> str:
    return datetime.now().strftime("%a %b %d %H:%M:%S %Y")


def mswineventlog_payload(
    os_module: str,
    event_id: int,
    event_source: str,
    account: str,
    account_type: str,
    action: str,
    category: str,
    body: str,
    seq: int | None = None,
) -> str:
    if seq is None:
        seq = random.randint(100000, 999999)
    fields = [
        "MSWinEventLog",
        "1",
        os_module,
        str(seq),
        _win_time_parts(),
        str(event_id),
        event_source,
        account,
        account_type,
        action,
        body,
    ]
    return "\t".join(fields)


class ActiveDirectorySource:
    id = "active_directory"
    label = "Active Directory (DC Security)"
    framing: Framing = "mswineventlog"
    pri_default = "<134>"
    os_family = "windows"

    def list_event_types(self) -> list[EventTypeSpec]:
        ids = ["4768", "4769", "4771", "4776", "4720", "4728", "4740"]
        return [EventTypeSpec(i, f"AD {i}", {"host_id": "string", "user_id": "string"}) for i in ids]

    def _dc(self, store: InventoryStore, params: dict[str, Any]):
        hid = params.get("host_id") or params.get("domain_controller_id")
        hosts = [h for h in store.list_hosts() if h.role == "domain_controller" or "dc" in (h.group or "").lower()]
        if not hosts:
            hosts = [h for h in store.list_hosts() if h.os_family == "windows"]
        by_id = {h.id: h for h in hosts}
        return by_id.get(hid or "") or (hosts[0] if hosts else None)

    def _user(self, store: InventoryStore, params: dict[str, Any]) -> tuple[str, str]:
        uid = params.get("user_id")
        users = store.list_users()
        by_id = {u.id: u for u in users}
        u = by_id.get(uid or "") or (users[0] if users else None)
        if not u:
            return "CORP", "admin"
        return (u.domain or "corp").upper(), u.sam

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory: InventoryStore | None = None) -> BuiltEvent:
        store = inventory or inventory_store
        h = self._dc(store, params)
        if not h:
            raise ValueError("Need a domain_controller host (or any windows host as fallback) in inventory")
        domain, user = self._user(store, params)
        reporting_ip = h.resolved_reporting_ip()
        hostname = h.hostname
        attacker = next((c.ip for c in store.list_c2() if c.role == "attacker" and c.ip), "185.231.88.45")

        if event_type == "4771":
            body = (
                "Kerberos pre-authentication failed. "
                f"Account Information: Account Name: {user} Account Domain: {domain} "
                f"Service Information: Service Name: krbtgt/{domain} "
                f"Network Information: Client Address: {attacker} "
                "Failure Information: Failure Code: 0x18 "
                "Status: The password provided for the package is incorrect."
            )
            payload_body = mswineventlog_payload(
                "Security",
                4771,
                "Microsoft-Windows-Security-Auditing",
                user,
                "User",
                "Failure Audit",
                "Kerberos Authentication Service",
                body,
            )
        elif event_type == "4768":
            body = f"A Kerberos authentication ticket (TGT) was requested. Account Name: {user} Client Address: {attacker}"
            payload_body = mswineventlog_payload(
                "Security",
                4768,
                "Microsoft-Windows-Security-Auditing",
                user,
                "User",
                "Information",
                "Kerberos Authentication Service",
                body,
            )
        elif event_type == "4769":
            body = f"A Kerberos service ticket was requested. Account Name: {user} Client Address: {attacker}"
            payload_body = mswineventlog_payload(
                "Security",
                4769,
                "Microsoft-Windows-Security-Auditing",
                user,
                "User",
                "Information",
                "Kerberos Service Ticket Operations",
                body,
            )
        elif event_type == "4776":
            body = (
                f"The domain controller attempted to validate credentials for account {domain}\\{user}. "
                f"The authentication package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 "
                f"Logon Account: {user} Source Workstation: WIN-REMOTE Source IP Address: {attacker}"
            )
            payload_body = mswineventlog_payload(
                "Security",
                4776,
                "Microsoft-Windows-Security-Auditing",
                user,
                "User",
                "Failure Audit",
                "Credential Validation",
                body,
            )
        elif event_type == "4720":
            body = f"A user account was created. Subject: Account Name: Administrator Account Domain: {domain} "
            body += f"New Account: Account Name: svc_bad Actor Account Domain: {domain}"
            payload_body = mswineventlog_payload(
                "Security",
                4720,
                "Microsoft-Windows-Security-Auditing",
                "Administrator",
                "User",
                "Success Audit",
                "User Account Management",
                body,
            )
        elif event_type == "4728":
            body = (
                f"A member was added to a security-enabled global group. "
                f"Subject: Administrator Domain: {domain} Member: Account Name: {user} Group: Domain Admins"
            )
            payload_body = mswineventlog_payload(
                "Security",
                4728,
                "Microsoft-Windows-Security-Auditing",
                user,
                "User",
                "Success Audit",
                "Security Group Management",
                body,
            )
        elif event_type == "4740":
            body = f"A user account was locked out. Subject: Administrator Domain: {domain} Account Name: {user}"
            payload_body = mswineventlog_payload(
                "Security",
                4740,
                "Microsoft-Windows-Security-Auditing",
                user,
                "User",
                "Information",
                "User Account Management",
                body,
            )
        else:
            raise ValueError(f"Unknown AD event_type {event_type}")

        pri = params.get("pri", self.pri_default)
        raw = f"{pri}{_syslog_ts()} {hostname} {payload_body}"
        return BuiltEvent(reporting_ip=reporting_ip, hostname=hostname, payload=raw, pri=str(pri), framing=self.framing)
