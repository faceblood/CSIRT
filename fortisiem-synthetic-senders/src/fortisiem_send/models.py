from __future__ import annotations

from dataclasses import dataclass


@dataclass
class UserAD:
    samaccountname: str
    email: str
    domain: str
    sid: str


@dataclass
class VMwareUser:
    username: str
    realm: str
    email: str
    role: str


@dataclass
class Asset:
    ip: str
    hostname: str
    os: str
    source_type: str
    serial_number: str = ""
    fortigate_devname: str = ""
    fortigate_serial: str = ""
    edr_tenant: str = ""
    edr_site: str = ""
    edr_mssp_mode: str = ""
    vmware_role: str = ""
    vmware_datacenter: str = ""
    vmware_cluster: str = ""


@dataclass
class Template:
    source: str
    category: str
    event_name: str
    severity: str
    action: str
    weight: int
    template: str


@dataclass
class RenderStep:
    """Minimal step view for template rendering (no campaign metadata)."""

    src_role: str = ""
    dst_role: str = ""
    asset_role: str = ""
    user_role: str = ""


@dataclass
class SendContext:
    run_id: str
    attacker_ip: str
    vpn_remote_ip: str
    c2_ip: str
    c2_domain: str
    user: UserAD
    vmware_user: VMwareUser
    initial_asset: Asset
    lateral_asset: Asset
    vmware_asset: Asset
    linux_asset: Asset
    fortigate_asset: Asset
    fortigate_devname: str
    fortigate_serial: str
    edr_tenant: str
    edr_site: str
    edr_mssp_mode: str
    custom_hostname: str
    encoded_commands: list[str]
    malware_name: str
    malware_family: str
    sequence_id: int = 0
