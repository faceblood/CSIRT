from __future__ import annotations

import random
import uuid
from pathlib import Path

from .asset_utils import find_asset_by_ip, find_user_by_sam, find_vmware_user, pick_asset
from .constants import DEFAULT_DOMAIN, DEFAULT_FORTIEDR_SITE, DEFAULT_FORTIEDR_TENANT
from .csv_io import load_csv
from .ip_utils import choose_attacker_ip
from .models import Asset, SendContext, Template, UserAD, VMwareUser


def load_users(base: Path) -> list[UserAD]:
    rows = load_csv(base / "config" / "users_ad.csv")
    if not rows:
        rows = [
            {"samaccountname": "jgarcia", "email": "jgarcia@age.local"},
            {"samaccountname": "admin.soc", "email": "admin.soc@age.local"},
        ]
    result: list[UserAD] = []
    for r in rows:
        email = r["email"].strip()
        domain = DEFAULT_DOMAIN
        sid = f"S-1-5-21-{random.randint(1000000000, 1999999999)}-{random.randint(1000, 9999)}"
        result.append(UserAD(r["samaccountname"].strip(), email, domain, sid))
    return result


def load_vmware_users(base: Path) -> list[VMwareUser]:
    rows = load_csv(base / "config" / "vmware_users.csv")
    if not rows:
        rows = [
            {
                "username": "administrator",
                "realm": "vsphere.local",
                "email": "administrator@vsphere.local",
                "role": "admin",
            }
        ]
    return [VMwareUser(r["username"], r["realm"], r["email"], r["role"]) for r in rows]


def load_assets(base: Path) -> list[Asset]:
    rows = load_csv(base / "config" / "assets.csv")
    if not rows:
        rows = [
            {"ip": "10.10.10.21", "hostname": "WIN-IT-001", "os": "Windows", "source_type": "windows"},
            {"ip": "10.10.50.10", "hostname": "LINUX-WEB-01", "os": "Linux", "source_type": "linux"},
            {"ip": "10.10.60.10", "hostname": "VCENTER-01", "os": "VMware", "source_type": "vmware"},
        ]
    assets: list[Asset] = []
    for r in rows:
        serial_number = (r.get("serial_number") or r.get("devid") or r.get("serial") or "").strip()
        fortigate_serial = (r.get("fortigate_serial") or serial_number).strip()
        fortigate_devname = (r.get("fortigate_devname") or r.get("hostname") or "").strip()
        assets.append(
            Asset(
                ip=r["ip"],
                hostname=r["hostname"],
                os=r["os"],
                source_type=r["source_type"],
                serial_number=serial_number,
                fortigate_devname=fortigate_devname,
                fortigate_serial=fortigate_serial,
                edr_tenant=(r.get("edr_tenant") or "").strip(),
                edr_site=(r.get("edr_site") or "").strip(),
                edr_mssp_mode=(r.get("edr_mssp_mode") or "").strip(),
                vmware_role=(r.get("vmware_role") or "").strip(),
                vmware_datacenter=(r.get("vmware_datacenter") or "").strip(),
                vmware_cluster=(r.get("vmware_cluster") or "").strip(),
            )
        )
    return assets


def load_simple_values(base: Path, name: str, key: str, default: list[str]) -> list[str]:
    rows = load_csv(base / "config" / name)
    if not rows:
        return default
    return [r[key] for r in rows if r.get(key)]


def load_templates(base: Path) -> list[Template]:
    repo = base / "log_repository"
    templates: list[Template] = []
    for path in repo.rglob("*.csv"):
        if path.parent.name == "campaigns":
            continue
        for row in load_csv(path):
            try:
                templates.append(
                    Template(
                        source=row["source"],
                        category=row["category"],
                        event_name=row["event_name"],
                        severity=row.get("severity", "medium"),
                        action=row.get("action", "detect"),
                        weight=int(row.get("weight", "1")),
                        template=row["template"],
                    )
                )
            except KeyError:
                continue
    return templates


def load_supporting_data(base: Path) -> tuple[list[dict[str, str]], list[str], list[str], list[str]]:
    malwares = load_csv(base / "config" / "malware_samples.csv") or [
        {"name": "Suspicious/EncodedPowerShell", "family": "PowerShell"}
    ]
    c2_ips = load_simple_values(base, "c2_ips.csv", "ip", ["45.9.148.10"])
    c2_domains = load_simple_values(base, "c2_domains.csv", "domain", ["cdn-update-security.example"])
    encoded_commands = load_simple_values(
        base,
        "powershell_encoded_commands.csv",
        "encoded_command",
        [
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
        ],
    )
    return malwares, c2_ips, c2_domains, encoded_commands


def build_send_context(
    base: Path,
    *,
    user_samaccountname: str = "",
    vmware_user_spec: str = "",
    endpoint_ip: str = "",
    initial_asset_ip: str = "",
    initial_asset_hostname: str = "",
    lateral_asset_ip: str = "",
    vmware_asset_ip: str = "",
    linux_asset_ip: str = "",
    fortigate_devname: str = "",
    fortigate_serial: str = "",
    hostname: str = "",
    attacker_ip: str = "",
    src_ip_mode: str = "random",
    vpn_remote_ip: str = "",
    c2_ip: str = "",
    c2_domain: str = "",
    active_sources: frozenset[str],
    run_label: str = "send",
) -> SendContext:
    users = load_users(base)
    vmware_users = load_vmware_users(base)
    assets = load_assets(base)
    malwares, c2_ips, c2_domains, encoded_commands = load_supporting_data(base)

    user = random.choice(users)
    if user_samaccountname:
        forced_user = find_user_by_sam(users, user_samaccountname)
        if forced_user is None:
            raise ValueError(
                f"user-samaccountname no encontrado en users_ad.csv: {user_samaccountname}"
            )
        user = forced_user

    vmware_user = random.choice(vmware_users)
    if vmware_user_spec:
        forced_vm_user = find_vmware_user(vmware_users, vmware_user_spec)
        if forced_vm_user is None:
            raise ValueError(
                f"vmware-user no encontrado en vmware_users.csv: {vmware_user_spec}"
            )
        vmware_user = forced_vm_user

    initial_asset = pick_asset(assets, "windows", assets[0])
    endpoint = (endpoint_ip or initial_asset_ip).strip()
    if endpoint:
        forced_initial = find_asset_by_ip(assets, endpoint)
        if forced_initial is None:
            generated_hostname = (
                initial_asset_hostname.strip()
                or hostname.strip()
                or f"ENDPOINT-{endpoint.replace('.', '-')}"
            )
            forced_initial = Asset(
                ip=endpoint,
                hostname=generated_hostname,
                os="Windows",
                source_type="windows",
                serial_number="",
            )
        initial_asset = forced_initial
    if initial_asset_hostname:
        initial_asset = Asset(
            ip=initial_asset.ip,
            hostname=initial_asset_hostname.strip(),
            os=initial_asset.os,
            source_type=initial_asset.source_type,
            serial_number=initial_asset.serial_number,
        )

    lateral_asset = pick_asset(assets, "windows", initial_asset)
    if lateral_asset_ip:
        forced_lateral = find_asset_by_ip(assets, lateral_asset_ip)
        if forced_lateral is None:
            raise ValueError(f"lateral-asset-ip no encontrado en assets.csv: {lateral_asset_ip}")
        lateral_asset = forced_lateral

    vmware_asset = pick_asset(assets, "vmware", initial_asset)
    if vmware_asset_ip:
        forced_vmware_asset = find_asset_by_ip(assets, vmware_asset_ip)
        if forced_vmware_asset is None:
            raise ValueError(f"vmware-asset-ip no encontrado en assets.csv: {vmware_asset_ip}")
        vmware_asset = forced_vmware_asset

    linux_asset = pick_asset(assets, "linux", initial_asset)
    if linux_asset_ip:
        forced_linux_asset = find_asset_by_ip(assets, linux_asset_ip)
        if forced_linux_asset is None:
            raise ValueError(f"linux-asset-ip no encontrado en assets.csv: {linux_asset_ip}")
        linux_asset = forced_linux_asset

    fortigate_asset = pick_asset(assets, "fortigate", initial_asset)
    custom_hostname = hostname.strip()
    resolved_fortigate_devname = (
        fortigate_devname.strip()
        if fortigate_devname
        else (custom_hostname or fortigate_asset.fortigate_devname or fortigate_asset.hostname)
    )
    resolved_fortigate_serial = (
        fortigate_serial.strip()
        if fortigate_serial
        else (fortigate_asset.fortigate_serial or fortigate_asset.serial_number)
    )
    if "fortigate" in active_sources and (not resolved_fortigate_devname or not resolved_fortigate_serial):
        raise ValueError(
            "FortiGate devname/serial requeridos para logs fortigate. "
            "Definelos en config/assets.csv (hostname/serial_number) o usa "
            "--fortigate-devname y --fortigate-serial."
        )

    edr_tenant = initial_asset.edr_tenant or DEFAULT_FORTIEDR_TENANT
    edr_site = initial_asset.edr_site or DEFAULT_FORTIEDR_SITE
    edr_mssp_mode = initial_asset.edr_mssp_mode or "false"

    if attacker_ip.strip():
        resolved_attacker = attacker_ip.strip()
    elif src_ip_mode not in {"random", "asset"}:
        resolved_attacker = src_ip_mode
    else:
        resolved_attacker = choose_attacker_ip(src_ip_mode, assets)

    if vpn_remote_ip.strip():
        resolved_vpn_remote = vpn_remote_ip.strip()
    elif attacker_ip.strip():
        resolved_vpn_remote = attacker_ip.strip()
    else:
        resolved_vpn_remote = choose_attacker_ip("random", assets)

    resolved_c2_ip = c2_ip.strip() if c2_ip else random.choice(c2_ips)
    resolved_c2_domain = c2_domain.strip() if c2_domain else random.choice(c2_domains)

    malware = random.choice(malwares)

    return SendContext(
        run_id=f"{run_label}-{uuid.uuid4().hex[:8]}",
        attacker_ip=resolved_attacker,
        vpn_remote_ip=resolved_vpn_remote,
        c2_ip=resolved_c2_ip,
        c2_domain=resolved_c2_domain,
        user=user,
        vmware_user=vmware_user,
        initial_asset=initial_asset,
        lateral_asset=lateral_asset,
        vmware_asset=vmware_asset,
        linux_asset=linux_asset,
        fortigate_asset=fortigate_asset,
        fortigate_devname=resolved_fortigate_devname,
        fortigate_serial=resolved_fortigate_serial,
        edr_tenant=edr_tenant,
        edr_site=edr_site,
        edr_mssp_mode=edr_mssp_mode,
        custom_hostname=custom_hostname,
        encoded_commands=encoded_commands,
        malware_name=malware.get("name", "Generic.Malware"),
        malware_family=malware.get("family", "Generic"),
    )
