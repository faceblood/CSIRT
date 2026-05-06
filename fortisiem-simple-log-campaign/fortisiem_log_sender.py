#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_TARGET = "10.255.9.3"
DEFAULT_PORT = 514
DEFAULT_RATE = 5
DEFAULT_HOSTNAME = "fortisiem-log-sender"
DEFAULT_SEND_MODE = "scapy"
SUPPORTED_CAMPAIGNS = {
    "phishing",
    "ransomware",
    "apt",
    "bruteforce",
    "vmware-compromise",
    "mixed",
    "ransomware-roles-example",
}
SUPPORTED_SOURCES = {"fortigate", "fortimail", "windows", "linux", "fortiedr", "vmware"}


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
class CampaignStep:
    step: int
    source: str
    category: str
    event_hint: str
    repeat: int
    phase: str = ""
    src_role: str = ""
    dst_role: str = ""
    asset_role: str = ""
    user_role: str = ""


@dataclass
class CampaignContext:
    campaign_id: str
    attacker_ip: str
    c2_ip: str
    c2_domain: str
    user: UserAD
    vmware_user: VMwareUser
    initial_asset: Asset
    lateral_asset: Asset
    vmware_asset: Asset
    linux_asset: Asset
    malware_name: str
    malware_family: str
    sequence_id: int = 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple FortiSIEM synthetic log campaign sender")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE)
    parser.add_argument("--campaign", required=True, choices=sorted(SUPPORTED_CAMPAIGNS))
    parser.add_argument("--sources", default="fortigate,fortimail,windows,linux,fortiedr,vmware")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--duration", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--print-raw", action="store_true")
    parser.add_argument("--src-ip-mode", default="random", choices=["random", "asset"])
    parser.add_argument("--send-mode", default=DEFAULT_SEND_MODE, choices=["scapy"])
    parser.add_argument("--step-mode", action="store_true")
    parser.add_argument("--explain-campaign", action="store_true")
    parser.add_argument("--timeline-out", default="")
    return parser.parse_args()


def parse_duration(text: str) -> int:
    if not text:
        return 0
    match = re.fullmatch(r"(\d+)([smh])", text.strip().lower())
    if not match:
        raise ValueError("Duration must be like 30s, 10m, 1h")
    value = int(match.group(1))
    unit = match.group(2)
    if unit == "s":
        return value
    if unit == "m":
        return value * 60
    return value * 3600


def format_rfc3164(hostname: str, message: str) -> str:
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return f"<134>{ts} {hostname} fortisiem-log-sender: {message}"


def send_syslog_scapy(target: str, port: int, message: str, src_ip: str | None) -> None:
    try:
        from scapy.all import IP, UDP, Raw, send  # type: ignore
    except Exception as exc:
        raise RuntimeError("Scapy no instalado. Ejecuta: pip install scapy") from exc
    packet = IP(src=src_ip, dst=target) / UDP(
        sport=random.randint(1024, 65535),
        dport=port,
    ) / Raw(load=message.encode("utf-8"))
    send(packet, verbose=False)


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return [dict(row) for row in csv.DictReader(f)]


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
        domain = email.split("@", 1)[1] if "@" in email else "age.local"
        sid = f"S-1-5-21-{random.randint(1000000000, 1999999999)}-{random.randint(1000,9999)}"
        result.append(UserAD(r["samaccountname"].strip(), email, domain, sid))
    return result


def load_vmware_users(base: Path) -> list[VMwareUser]:
    rows = load_csv(base / "config" / "vmware_users.csv")
    if not rows:
        rows = [
            {"username": "administrator", "realm": "vsphere.local", "email": "administrator@vsphere.local", "role": "admin"}
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
    return [Asset(r["ip"], r["hostname"], r["os"], r["source_type"]) for r in rows]


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


def load_campaign_steps(base: Path, campaign: str) -> list[CampaignStep]:
    file_name = campaign.replace("-", "_") + ".csv"
    rows = load_csv(base / "log_repository" / "campaigns" / file_name)
    if not rows:
        return []
    steps = []
    for r in rows:
        steps.append(
            CampaignStep(
                step=int(r["step"]),
                source=r["source"],
                category=r["category"],
                event_hint=r["event_hint"],
                repeat=int(r.get("repeat", "1")),
                phase=r.get("phase", ""),
                src_role=r.get("src_role", ""),
                dst_role=r.get("dst_role", ""),
                asset_role=r.get("asset_role", ""),
                user_role=r.get("user_role", ""),
            )
        )
    return sorted(steps, key=lambda s: s.step)


def choose_attacker_ip(mode: str, assets: list[Asset]) -> str:
    if mode == "asset":
        return random.choice(assets).ip
    first = random.randint(11, 223)
    return f"{first}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def pick_asset(assets: list[Asset], source_type: str, fallback: Asset) -> Asset:
    selected = [a for a in assets if a.source_type == source_type]
    return random.choice(selected) if selected else fallback


def select_template(templates: list[Template], source: str, category: str, hint: str) -> Template | None:
    filtered = [t for t in templates if t.source == source and t.category == category]
    if not filtered:
        return None
    exact = [t for t in filtered if t.event_name.lower() == hint.lower()]
    pool = exact if exact else [t for t in filtered if hint.lower() in t.event_name.lower()]
    if not pool:
        pool = filtered
    return random.choices(pool, weights=[max(1, t.weight) for t in pool], k=1)[0]


def _resolve_ip_from_role(role: str, ctx: CampaignContext, source: str) -> str:
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


def _resolve_asset_from_role(role: str, ctx: CampaignContext, source: str) -> Asset:
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


def _resolve_user_from_role(role: str, ctx: CampaignContext, source: str) -> str:
    role = (role or "").strip().lower()
    if role == "vmware_user" or source == "vmware":
        return f"{ctx.vmware_user.username}@{ctx.vmware_user.realm}"
    return f"{ctx.user.samaccountname}@{ctx.user.domain}"


def _resolve_step_view(step: CampaignStep, ctx: CampaignContext) -> dict[str, str]:
    src_ip = _resolve_ip_from_role(step.src_role, ctx, step.source)
    dst_ip = _resolve_ip_from_role(step.dst_role, ctx, step.source)
    asset = _resolve_asset_from_role(step.asset_role, ctx, step.source)
    user = _resolve_user_from_role(step.user_role, ctx, step.source)
    src_role = step.src_role or ("attacker" if step.source in {"fortigate", "fortimail", "vmware"} else "initial_asset")
    dst_role = step.dst_role or "default"
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "asset_name": asset.hostname,
        "user": user,
        "src_role": src_role,
        "dst_role": dst_role,
    }


def _print_campaign_explain(steps: list[CampaignStep], ctx: CampaignContext) -> None:
    print("\n=== Campaign Explain ===")
    print(f"Campaign ID: {ctx.campaign_id}")
    print(f"Attacker IP: {ctx.attacker_ip}")
    print(f"Initial Asset: {ctx.initial_asset.hostname} ({ctx.initial_asset.ip})")
    print(f"Lateral Asset: {ctx.lateral_asset.hostname} ({ctx.lateral_asset.ip})")
    print(f"VMware Asset: {ctx.vmware_asset.hostname} ({ctx.vmware_asset.ip})")
    print(f"C2: {ctx.c2_domain} ({ctx.c2_ip})")
    print(f"User: {ctx.user.samaccountname}@{ctx.user.domain}")
    print(f"VMware User: {ctx.vmware_user.username}@{ctx.vmware_user.realm}")
    print("\nSteps:")
    for idx, step in enumerate(steps, start=1):
        view = _resolve_step_view(step, ctx)
        phase = step.phase or "n/a"
        print(
            f"{idx:02d}. phase={phase} source={step.source} category={step.category} "
            f"event='{step.event_hint}' flow={view['src_role']}->{view['dst_role']} "
            f"src={view['src_ip']} dst={view['dst_ip'] or 'N/A'} repeat={step.repeat}"
        )
    print("========================\n")


def _write_timeline(path_str: str, entries: list[dict[str, Any]]) -> None:
    if not path_str:
        return
    path = Path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix.lower()
    if suffix == ".json":
        with path.open("w", encoding="utf-8") as f:
            json.dump(entries, f, ensure_ascii=False, indent=2)
        return
    # Default CSV
    if not entries:
        with path.open("w", encoding="utf-8", newline="") as f:
            f.write("timestamp,campaign_id,step,phase,source,category,event_hint,src_role,dst_role,src_ip,dst_ip,asset,user,raw\n")
        return
    keys = [
        "timestamp",
        "campaign_id",
        "step",
        "phase",
        "source",
        "category",
        "event_hint",
        "src_role",
        "dst_role",
        "src_ip",
        "dst_ip",
        "asset",
        "user",
        "raw",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for e in entries:
            writer.writerow({k: e.get(k, "") for k in keys})


def render(template: str, ctx: CampaignContext, source: str, step: CampaignStep) -> tuple[str, str]:
    ctx.sequence_id += 1
    now = datetime.now()
    src_ip = _resolve_ip_from_role(step.src_role, ctx, source)
    dst_ip = _resolve_ip_from_role(step.dst_role, ctx, source)
    asset = _resolve_asset_from_role(step.asset_role, ctx, source)
    host = asset.hostname
    asset_ip = asset.ip
    user_full = _resolve_user_from_role(step.user_role, ctx, source)
    command_line = random.choice(
        [
            "powershell -NoP -W Hidden -EncodedCommand <synthetic_value>",
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


def maybe_step_prompt(step: CampaignStep, total: int, idx: int, ctx: CampaignContext) -> str:
    view = _resolve_step_view(step, ctx)
    print(f"\n[Campaign: {ctx.campaign_id}]")
    print(f"[Step {idx}/{total}]")
    print(f"Source: {step.source}")
    print(f"Category: {step.category}")
    if step.phase:
        print(f"Phase: {step.phase}")
    print(f"Event: {step.event_hint}")
    print(f"Repeat: {step.repeat}")
    print(f"Flow: {view['src_role']} -> {view['dst_role']}")
    print(f"Src IP: {view['src_ip']}")
    print(f"Dst IP: {view['dst_ip'] or 'N/A'}")
    print(f"Asset: {view['asset_name']}")
    print(f"User: {view['user']}")
    print("ENTER = ejecutar | s = saltar | r = repetir anterior | q = salir")
    return input("> ").strip().lower()


def run_campaign(args: argparse.Namespace, base: Path) -> int:
    sources = {s.strip() for s in args.sources.split(",") if s.strip()}
    unknown = sources - SUPPORTED_SOURCES
    if unknown:
        raise ValueError(f"Fuentes no soportadas: {sorted(unknown)}")

    users = load_users(base)
    vmware_users = load_vmware_users(base)
    assets = load_assets(base)
    malwares = load_csv(base / "config" / "malware_samples.csv") or [{"name": "Suspicious/EncodedPowerShell", "family": "PowerShell"}]
    c2_ips = load_simple_values(base, "c2_ips.csv", "ip", ["45.9.148.10"])
    c2_domains = load_simple_values(base, "c2_domains.csv", "domain", ["cdn-update-security.example"])
    templates = load_templates(base)
    steps = load_campaign_steps(base, args.campaign)
    if not steps:
        raise RuntimeError(f"No steps found for campaign '{args.campaign}'")

    user = random.choice(users)
    vmware_user = random.choice(vmware_users)
    initial_asset = pick_asset(assets, "windows", assets[0])
    lateral_asset = pick_asset(assets, "windows", initial_asset)
    vmware_asset = pick_asset(assets, "vmware", initial_asset)
    linux_asset = pick_asset(assets, "linux", initial_asset)
    malware = random.choice(malwares)
    ctx = CampaignContext(
        campaign_id=f"{args.campaign}-{uuid.uuid4().hex[:8]}",
        attacker_ip=choose_attacker_ip(args.src_ip_mode, assets),
        c2_ip=random.choice(c2_ips),
        c2_domain=random.choice(c2_domains),
        user=user,
        vmware_user=vmware_user,
        initial_asset=initial_asset,
        lateral_asset=lateral_asset,
        vmware_asset=vmware_asset,
        linux_asset=linux_asset,
        malware_name=malware.get("name", "Generic.Malware"),
        malware_family=malware.get("family", "Generic"),
    )
    if args.explain_campaign:
        _print_campaign_explain(steps, ctx)

    rate_sleep = 1.0 / max(1, args.rate)
    duration_sec = parse_duration(args.duration) if args.duration else 0
    start_ts = time.time()
    sent = 0
    idx = 0
    previous: CampaignStep | None = None
    timeline: list[dict[str, Any]] = []

    while True:
        for i, step in enumerate(steps, start=1):
            if step.source not in sources:
                continue
            current = step
            if args.step_mode:
                action = maybe_step_prompt(step, len(steps), i, ctx)
                if action == "q":
                    return sent
                if action == "s":
                    previous = step
                    continue
                if action == "r" and previous is not None:
                    current = previous
            template = select_template(templates, current.source, current.category, current.event_hint)
            if template is None:
                previous = current
                continue
            for _ in range(max(1, current.repeat)):
                raw, src_ip = render(template.template, ctx, current.source, current)
                wire = format_rfc3164(DEFAULT_HOSTNAME, raw)
                view = _resolve_step_view(current, ctx)
                if args.print_raw:
                    print(raw)
                if not args.dry_run:
                    send_syslog_scapy(args.target, args.port, wire, src_ip=src_ip)
                timeline.append(
                    {
                        "timestamp": datetime.now().isoformat(timespec="seconds"),
                        "campaign_id": ctx.campaign_id,
                        "step": current.step,
                        "phase": current.phase,
                        "source": current.source,
                        "category": current.category,
                        "event_hint": current.event_hint,
                        "src_role": view["src_role"],
                        "dst_role": view["dst_role"],
                        "src_ip": view["src_ip"],
                        "dst_ip": view["dst_ip"] or "N/A",
                        "asset": view["asset_name"],
                        "user": view["user"],
                        "raw": raw,
                    }
                )
                sent += 1
                idx += 1
                if args.count and sent >= args.count:
                    _write_timeline(args.timeline_out, timeline)
                    return sent
                if duration_sec and (time.time() - start_ts) >= duration_sec:
                    _write_timeline(args.timeline_out, timeline)
                    return sent
                if not args.step_mode:
                    time.sleep(rate_sleep)
            print(f"Executed step {i}/{len(steps)} | Generated events: {max(1, current.repeat)}")
            previous = current
        if not args.loop:
            break
    _write_timeline(args.timeline_out, timeline)
    return sent


def main() -> int:
    args = parse_args()
    base = Path(__file__).resolve().parent
    try:
        total = run_campaign(args, base)
    except KeyboardInterrupt:
        print("\nInterrumpido por usuario.")
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Done. Total events processed: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
