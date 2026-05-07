from __future__ import annotations

import random
from datetime import datetime
from typing import Any

from .models import Asset, RenderStep, SendContext


def _resolve_ip_from_role(role: str, ctx: SendContext, source: str) -> str:
    role = (role or "").strip().lower()
    if not role:
        return ctx.attacker_ip if source in {"fortigate", "fortimail", "vmware"} else ctx.initial_asset.ip
    if role == "attacker":
        return ctx.attacker_ip
    if role == "initial_asset":
        return ctx.initial_asset.ip
    if role == "lateral_asset":
        return ctx.lateral_asset.ip
    if role == "c2":
        return ctx.c2_ip
    if role == "vcenter":
        return ctx.vmware_asset.ip
    if role == "linux":
        return ctx.linux_asset.ip
    if role == "none":
        return ""
    return ctx.initial_asset.ip


def _resolve_asset_from_role(role: str, ctx: SendContext, source: str) -> Asset:
    role = (role or "").strip().lower()
    if not role:
        if source == "linux":
            return ctx.linux_asset
        if source == "vmware":
            return ctx.vmware_asset
        return ctx.initial_asset
    if role == "initial_asset":
        return ctx.initial_asset
    if role == "lateral_asset":
        return ctx.lateral_asset
    if role == "vcenter":
        return ctx.vmware_asset
    if role == "linux":
        return ctx.linux_asset
    return ctx.initial_asset


def _resolve_user_from_role(role: str, ctx: SendContext, source: str) -> str:
    role = (role or "").strip().lower()
    if role == "vmware_user" or source == "vmware":
        return f"{ctx.vmware_user.username}@{ctx.vmware_user.realm}"
    return f"{ctx.user.samaccountname}@{ctx.user.domain}"


def render(template: str, ctx: SendContext, source: str, step: RenderStep) -> tuple[str, str]:
    ctx.sequence_id += 1
    now = datetime.now()
    src_ip = _resolve_ip_from_role(step.src_role, ctx, source)
    dst_ip = _resolve_ip_from_role(step.dst_role, ctx, source) if step.dst_role else ""
    asset = _resolve_asset_from_role(step.asset_role, ctx, source)
    host = ctx.fortigate_devname if source == "fortigate" else (ctx.custom_hostname or asset.hostname)
    asset_ip = asset.ip
    user_full = _resolve_user_from_role(step.user_role, ctx, source)
    command_line = random.choice(
        [
            random.choice(ctx.encoded_commands),
            "vssadmin delete shadows /all /quiet",
            "wbadmin delete catalog -quiet",
            "ipconfig /all",
            "whoami /all",
        ]
    )
    mapping: dict[str, Any] = {
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "timestamp": now.isoformat(timespec="seconds"),
        "src_ip": src_ip,
        "vpn_remote_ip": ctx.vpn_remote_ip,
        "dst_ip": dst_ip or asset_ip,
        "asset_ip": asset_ip,
        "hostname": host,
        "domain": ctx.user.domain,
        "username": ctx.user.samaccountname,
        "email": ctx.user.email,
        "user_full": user_full,
        "malware_name": ctx.malware_name,
        "malware_family": ctx.malware_family,
        "c2_ip": ctx.c2_ip,
        "c2_domain": ctx.c2_domain,
        "vcenter_ip": ctx.vmware_asset.ip,
        "fortigate_ip": ctx.fortigate_asset.ip,
        "fortigate_hostname": ctx.fortigate_devname,
        "fortigate_serial": ctx.fortigate_serial,
        "devid": ctx.fortigate_serial,
        "tenant": ctx.edr_tenant,
        "site": ctx.edr_site,
        "mssp_mode": ctx.edr_mssp_mode,
        "vmware_user": f"{ctx.vmware_user.username}@{ctx.vmware_user.realm}",
        "vm_name": random.choice(["VM-ERP-01", "VM-WEB-01", "VM-SOC-01"]),
        "esxi_host": random.choice(["ESXI-01", "ESXI-02"]),
        "datastore": random.choice(["datastore-prod-01", "datastore-backup-01"]),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([22, 53, 80, 443, 445]),
        "pid": random.randint(1000, 65000),
        "opid": random.randint(1000, 9999),
        "command_line": command_line,
    }
    try:
        return template.format(**mapping), src_ip
    except Exception:
        return template, src_ip
