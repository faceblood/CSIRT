#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Operación Nodo Esencial - Emisor consolidado para FortiSIEM

Fuentes simuladas:
  loggen-fw01     10.0.20.101
  loggen-dns01    10.0.20.102
  loggen-proxy01  10.0.20.103
  loggen-edr01    10.0.20.104

Destino FortiSIEM:
  10.255.9.202:514/UDP

Incluye:
  - Firewall genérico tipo FortiGate-like
  - DNS genérico tipo BIND-like
  - Proxy genérico tipo Squid-like
  - FortiEDR en formato CEF

Uso por fase:
  sudo python3 nodo_esencial_sender.py --phase baseline --count 100 --eps 1
  sudo python3 nodo_esencial_sender.py --phase initial  --count 120 --eps 2
  sudo python3 nodo_esencial_sender.py --phase identity --count 120 --eps 2
  sudo python3 nodo_esencial_sender.py --phase esxi     --count 80  --eps 2
  sudo python3 nodo_esencial_sender.py --phase backup   --count 100 --eps 2
  sudo python3 nodo_esencial_sender.py --phase impact   --count 80  --eps 2
  sudo python3 nodo_esencial_sender.py --phase incident --count 300 --eps 3

Uso secuencia completa:
  sudo python3 nodo_esencial_sender.py --sequence

Requisitos:
  pip install scapy
"""

import argparse
import random
import time
from datetime import datetime, timezone

from scapy.all import IP, UDP, Raw, send


# ============================================================
# CONFIGURACIÓN FIJA
# ============================================================

SIEM_IP = "10.255.9.3"
SIEM_PORT = 514

LOG_SOURCES = {
    "fw": {
        "hostname": "loggen-fw01",
        "ip": "10.0.20.101",
    },
    "dns": {
        "hostname": "loggen-dns01",
        "ip": "10.0.20.102",
    },
    "proxy": {
        "hostname": "loggen-proxy01",
        "ip": "10.0.20.103",
    },
    "edr": {
        "hostname": "loggen-edr01",
        "ip": "10.255.9.202",
    },
}

FORTIEDR_ORG = "1"
FORTIEDR_ORG_ID = "1"


# ============================================================
# ENTORNO SIMULADO
# ============================================================

CLIENTS = [
    "10.0.30.10",
    "10.0.30.11",
    "10.0.30.12",
    "10.0.30.20",
    "10.0.30.21",
]

SERVERS = {
    "APP-LNX-01": "10.0.40.10",
    "DB-LNX-01": "10.0.40.11",
    "DC-WIN-01": "10.0.40.20",
    "FILE-WIN-01": "10.0.40.21",
    "JUMP-WIN-01": "10.0.40.22",
    "BACKUP-WIN-01": "10.0.40.23",
    "MON-LNX-01": "10.0.40.30",
    "ESXI-HOST-01": "10.0.50.10",
}

HOST_OS = {
    "APP-LNX-01": "Ubuntu Server 22.04",
    "DB-LNX-01": "Ubuntu Server 22.04",
    "MON-LNX-01": "Ubuntu Server 22.04",
    "DC-WIN-01": "Windows Server 2019",
    "FILE-WIN-01": "Windows Server 2019",
    "JUMP-WIN-01": "Windows Server 2019",
    "BACKUP-WIN-01": "Windows Server 2019",
    "ESXI-HOST-01": "VMware ESXi",
}

USERS = [
    "svc_webapp",
    "svc_backup",
    "admin.local",
    "proveedor_soporte",
    "j.garcia",
    "m.lopez",
    "operador_noc",
]

EXTERNAL_IPS = [
    "198.51.100.10",
    "198.51.100.22",
    "203.0.113.15",
    "203.0.113.44",
    "192.0.2.55",
]

DOMAINS_NORMAL = [
    "portal-servicios.local",
    "auth.corp.local",
    "backup.internal.local",
    "monitoring.internal.local",
    "updates.vendor.local",
    "repo.linux.local",
    "cdn.example.net",
    "api.example.net",
]

DOMAINS_RARE = [
    "cdn-update-check.example.net",
    "telemetry-sync.example.org",
    "storage-gateway.example.net",
    "fileshare-sync.example.org",
]


# ============================================================
# UTILIDADES
# ============================================================

def syslog_ts():
    return datetime.now().strftime("%b %d %H:%M:%S")


def edr_time():
    return datetime.now(timezone.utc).strftime("%d-%m-%Y, %H:%M:%S")


def cef_escape(value):
    value = str(value)
    return (
        value
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def rfc3164(hostname, message, pri=134):
    return f"<{pri}>{syslog_ts()} {hostname} {message}"


def random_server():
    name = random.choice(list(SERVERS.keys()))
    return name, SERVERS[name]


# ============================================================
# FIREWALL GENÉRICO
# ============================================================

def fw_allow_traffic():
    src = random.choice(CLIENTS)
    dst_name, dst_ip = random_server()
    port = random.choice([53, 80, 88, 389, 443, 445, 8080, 3389])
    proto = "tcp" if port not in [53, 88] else random.choice(["tcp", "udp"])

    msg = (
        f'date={datetime.now().strftime("%Y-%m-%d")} '
        f'time={datetime.now().strftime("%H:%M:%S")} '
        f'devname="loggen-fw01" '
        f'devid="FGT000000001" '
        f'type="traffic" subtype="forward" level="notice" '
        f'srcip={src} dstip={dst_ip} dstname="{dst_name}" '
        f'srcport={random.randint(20000, 65000)} dstport={port} '
        f'proto={proto} action="accept" policyid=10 '
        f'service="{port}/{proto}" '
        f'sentbyte={random.randint(500, 50000)} '
        f'rcvdbyte={random.randint(500, 50000)}'
    )

    return "fw", rfc3164(LOG_SOURCES["fw"]["hostname"], msg)


def fw_deny_esxi():
    src = random.choice([SERVERS["JUMP-WIN-01"]] + CLIENTS)

    msg = (
        f'date={datetime.now().strftime("%Y-%m-%d")} '
        f'time={datetime.now().strftime("%H:%M:%S")} '
        f'devname="loggen-fw01" '
        f'devid="FGT000000001" '
        f'type="traffic" subtype="forward" level="warning" '
        f'srcip={src} dstip={SERVERS["ESXI-HOST-01"]} dstname="ESXI-HOST-01" '
        f'srcport={random.randint(20000, 65000)} dstport=443 '
        f'proto=tcp action="deny" policyid=90 '
        f'service="HTTPS" msg="Denied by policy"'
    )

    return "fw", rfc3164(LOG_SOURCES["fw"]["hostname"], msg, pri=132)


def fw_outbound_unusual():
    src = random.choice([
        SERVERS["APP-LNX-01"],
        SERVERS["DB-LNX-01"],
        SERVERS["JUMP-WIN-01"],
    ])
    dst = random.choice(EXTERNAL_IPS)

    msg = (
        f'date={datetime.now().strftime("%Y-%m-%d")} '
        f'time={datetime.now().strftime("%H:%M:%S")} '
        f'devname="loggen-fw01" '
        f'devid="FGT000000001" '
        f'type="traffic" subtype="forward" level="notice" '
        f'srcip={src} dstip={dst} '
        f'srcport={random.randint(20000, 65000)} dstport=443 '
        f'proto=tcp action="accept" policyid=20 '
        f'service="HTTPS" '
        f'sentbyte={random.randint(3000000, 20000000)} '
        f'rcvdbyte={random.randint(500, 8000)}'
    )

    return "fw", rfc3164(LOG_SOURCES["fw"]["hostname"], msg)


# ============================================================
# DNS GENÉRICO
# ============================================================

def dns_query_normal():
    src = random.choice(CLIENTS + list(SERVERS.values()))
    domain = random.choice(DOMAINS_NORMAL)

    msg = (
        f'named[{random.randint(1000, 9999)}]: '
        f'client @{random.randint(100000, 999999)} {src}#'
        f'{random.randint(20000, 65000)} '
        f'query: {domain} IN A + '
        f'(10.0.20.102)'
    )

    return "dns", rfc3164(LOG_SOURCES["dns"]["hostname"], msg)


def dns_query_rare():
    src = random.choice([
        SERVERS["APP-LNX-01"],
        SERVERS["DB-LNX-01"],
        SERVERS["JUMP-WIN-01"],
    ])
    domain = random.choice(DOMAINS_RARE)

    msg = (
        f'named[{random.randint(1000, 9999)}]: '
        f'client @{random.randint(100000, 999999)} {src}#'
        f'{random.randint(20000, 65000)} '
        f'query: {domain} IN A + '
        f'(10.0.20.102)'
    )

    return "dns", rfc3164(LOG_SOURCES["dns"]["hostname"], msg)


def dns_nxdomain():
    src = random.choice(CLIENTS + list(SERVERS.values()))
    domain = f"{random.randint(10000,99999)}-{random.choice(DOMAINS_RARE)}"

    msg = (
        f'named[{random.randint(1000, 9999)}]: '
        f'client @{random.randint(100000, 999999)} {src}#'
        f'{random.randint(20000, 65000)} '
        f'query: {domain} IN A - '
        f'(10.0.20.102) NXDOMAIN'
    )

    return "dns", rfc3164(LOG_SOURCES["dns"]["hostname"], msg, pri=132)


# ============================================================
# PROXY GENÉRICO
# ============================================================

def proxy_access_normal():
    src = random.choice(CLIENTS)
    domain = random.choice(DOMAINS_NORMAL)
    status = random.choice(["TCP_MISS/200", "TCP_HIT/200", "TCP_TUNNEL/200"])

    msg = (
        f'{int(time.time())}.{random.randint(100, 999)} '
        f'{random.randint(10, 900)} {src} {status} '
        f'{random.randint(500, 200000)} '
        f'{random.choice(["GET", "POST", "CONNECT"])} '
        f'https://{domain}/ - HIER_DIRECT/{random.choice(EXTERNAL_IPS)} -'
    )

    return "proxy", rfc3164(LOG_SOURCES["proxy"]["hostname"], msg)


def proxy_large_post():
    src = random.choice([
        SERVERS["APP-LNX-01"],
        SERVERS["DB-LNX-01"],
    ])
    domain = random.choice(DOMAINS_RARE)

    msg = (
        f'{int(time.time())}.{random.randint(100, 999)} '
        f'{random.randint(800, 3000)} {src} TCP_MISS/200 '
        f'{random.randint(3000000, 25000000)} '
        f'POST https://{domain}/upload - '
        f'HIER_DIRECT/{random.choice(EXTERNAL_IPS)} application/octet-stream'
    )

    return "proxy", rfc3164(LOG_SOURCES["proxy"]["hostname"], msg, pri=132)


def proxy_blocked():
    src = random.choice(CLIENTS + [SERVERS["APP-LNX-01"]])
    domain = random.choice(DOMAINS_RARE)

    msg = (
        f'{int(time.time())}.{random.randint(100, 999)} '
        f'{random.randint(10, 500)} {src} TCP_DENIED/403 '
        f'{random.randint(100, 1000)} '
        f'CONNECT {domain}:443 - NONE/- text/html'
    )

    return "proxy", rfc3164(LOG_SOURCES["proxy"]["hostname"], msg, pri=132)


# ============================================================
# FORTIEDR CEF
# ============================================================

def fortiedr_cef(
    eventid,
    name,
    severity,
    host,
    user,
    process_name,
    process_path,
    classification,
    action,
    reason,
    src_ip=None,
    command_line=None,
    remote_connection=None,
    destination=None,
    event_target=None,
    threat_attack_id=None,
    mitre_tags=None,
    signed="yes",
    count=1,
):
    os_name = HOST_OS.get(host, "Unknown")
    raw_data_id = random.randint(100000, 999999)
    first_seen = edr_time()
    last_seen = first_seen

    header = (
        f"CEF:0|Fortinet|FortiEDR|7.2.3|"
        f"{cef_escape(eventid)}|{cef_escape(name)}|{severity}|"
    )

    fields = {
        "cs1Label": "Organization",
        "cs1": FORTIEDR_ORG,
        "cs2Label": "OrganizationId",
        "cs2": FORTIEDR_ORG_ID,
        "eventid": eventid,
        "cs6Label": "RawDataId",
        "cs6": raw_data_id,
        "shost": host,
        "cs5Label": "DeviceState",
        "cs5": "Running",
        "cs3Label": "OS",
        "cs3": os_name,
        "fname": process_name,
        "filePath": process_path,
        "Classification": classification,
        "dst": destination or SERVERS.get(host, ""),
        "deviceCustomDate1Label": "FirstSeen",
        "deviceCustomDate1": first_seen,
        "deviceCustomDate2Label": "LastSeen",
        "deviceCustomDate2": last_seen,
        "act": action,
        "cnt": count,
        "AppSigned": signed,
        "reason": reason,
        "suser": user,
        "deviceTranslatedAddress": src_ip or "",
        "EventCommandLine": command_line or "",
        "RemoteConnection": remote_connection or "",
        "threatAttackID": threat_attack_id or "",
        "frameworkName": "MITRE ATT&CK" if mitre_tags else "",
        "MitreTags": mitre_tags or "",
        "EventTarget": event_target or "",
    }

    extension = " ".join(
        f"{key}={cef_escape(value)}"
        for key, value in fields.items()
        if value != ""
    )

    return "edr", rfc3164(LOG_SOURCES["edr"]["hostname"], header + extension, pri=133)


# ============================================================
# EVENTOS FORTIEDR CEF
# ============================================================

def edr_login_success():
    host = random.choice(["DC-WIN-01", "JUMP-WIN-01", "FILE-WIN-01"])
    user = random.choice(USERS)
    src_ip = random.choice(CLIENTS)

    return fortiedr_cef(
        eventid=random.randint(100000, 199999),
        name="Logon Activity",
        severity=3,
        host=host,
        user=user,
        process_name="lsass.exe",
        process_path=r"C:\Windows\System32\lsass.exe",
        classification="Logon",
        action="Detected",
        reason="User logon activity observed",
        src_ip=src_ip,
        event_target=host,
    )


def edr_login_failure():
    host = random.choice(["DC-WIN-01", "JUMP-WIN-01", "FILE-WIN-01"])
    user = random.choice(USERS)
    src_ip = random.choice(CLIENTS + EXTERNAL_IPS)

    return fortiedr_cef(
        eventid=random.randint(200000, 299999),
        name="Failed Logon Activity",
        severity=4,
        host=host,
        user=user,
        process_name="lsass.exe",
        process_path=r"C:\Windows\System32\lsass.exe",
        classification="Logon",
        action="Detected",
        reason="Failed user logon activity observed",
        src_ip=src_ip,
        event_target=host,
    )


def edr_privileged_logon():
    host = random.choice(["DC-WIN-01", "JUMP-WIN-01"])
    user = random.choice(["admin.local", "proveedor_soporte"])
    src_ip = random.choice([SERVERS["JUMP-WIN-01"]] + CLIENTS)

    return fortiedr_cef(
        eventid=random.randint(300000, 399999),
        name="Privileged Logon",
        severity=6,
        host=host,
        user=user,
        process_name="lsass.exe",
        process_path=r"C:\Windows\System32\lsass.exe",
        classification="Suspicious",
        action="Detected",
        reason="Privileged account logon observed outside expected pattern",
        src_ip=src_ip,
        event_target=host,
        threat_attack_id="Valid Accounts",
        mitre_tags="T1078",
    )


def edr_powershell_activity():
    host = random.choice(["JUMP-WIN-01", "FILE-WIN-01"])
    user = random.choice(["admin.local", "proveedor_soporte"])

    return fortiedr_cef(
        eventid=random.randint(400000, 499999),
        name="PowerShell Execution",
        severity=7,
        host=host,
        user=user,
        process_name="powershell.exe",
        process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        classification="Suspicious",
        action="Detected",
        reason="PowerShell execution observed with unusual command line",
        command_line=r"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <redacted>",
        event_target=host,
        threat_attack_id="Command and Scripting Interpreter",
        mitre_tags="T1059.001",
    )


def edr_group_change():
    host = "DC-WIN-01"
    user = random.choice(["admin.local", "proveedor_soporte"])

    return fortiedr_cef(
        eventid=random.randint(500000, 599999),
        name="Privileged Group Modification",
        severity=8,
        host=host,
        user=user,
        process_name="net.exe",
        process_path=r"C:\Windows\System32\net.exe",
        classification="Suspicious",
        action="Detected",
        reason="Privileged group membership modification observed",
        command_line=r'net group "Domain Admins" svc_backup /add /domain',
        event_target="Domain Admins",
        threat_attack_id="Account Manipulation",
        mitre_tags="T1098",
    )


def edr_linux_process_activity():
    host = "APP-LNX-01"
    user = "svc_webapp"

    return fortiedr_cef(
        eventid=random.randint(600000, 699999),
        name="Linux Process Execution",
        severity=7,
        host=host,
        user=user,
        process_name="python3",
        process_path="/usr/bin/python3",
        classification="Suspicious",
        action="Detected",
        reason="Unexpected child process from web service account",
        command_line="/usr/bin/python3 /tmp/worker.py --check",
        event_target="/tmp/worker.py",
        threat_attack_id="Command and Scripting Interpreter",
        mitre_tags="T1059",
    )


def edr_outbound_connection():
    host = random.choice(["APP-LNX-01", "DB-LNX-01", "JUMP-WIN-01"])
    user = random.choice(["svc_webapp", "admin.local", "proveedor_soporte"])
    remote_ip = random.choice(EXTERNAL_IPS)

    if host in ["APP-LNX-01", "DB-LNX-01"]:
        process_name = "nginx"
        process_path = "/usr/sbin/nginx"
    else:
        process_name = "svchost.exe"
        process_path = r"C:\Windows\System32\svchost.exe"

    return fortiedr_cef(
        eventid=random.randint(700000, 799999),
        name="Outbound Network Connection",
        severity=6,
        host=host,
        user=user,
        process_name=process_name,
        process_path=process_path,
        classification="Suspicious",
        action="Detected",
        reason="Outbound connection to uncommon external address",
        remote_connection=f"{remote_ip}:443",
        destination=remote_ip,
        event_target=remote_ip,
        threat_attack_id="Application Layer Protocol",
        mitre_tags="T1071",
    )


def edr_backup_repository_access():
    host = "BACKUP-WIN-01"
    user = "svc_backup"

    return fortiedr_cef(
        eventid=random.randint(800000, 899999),
        name="Backup Repository Access",
        severity=8,
        host=host,
        user=user,
        process_name="backup-agent.exe",
        process_path=r"C:\Program Files\BackupAgent\backup-agent.exe",
        classification="Suspicious",
        action="Detected",
        reason="Backup repository enumeration activity observed",
        command_line=r'"C:\Program Files\BackupAgent\backup-agent.exe" list repositories',
        event_target="Backup Repository",
        threat_attack_id="Data from Local System",
        mitre_tags="T1005",
    )


def edr_file_rename_activity():
    host = "FILE-WIN-01"
    user = random.choice(["svc_backup", "admin.local", "proveedor_soporte"])

    return fortiedr_cef(
        eventid=random.randint(900000, 999999),
        name="Suspicious File Modification",
        severity=9,
        host=host,
        user=user,
        process_name="cmd.exe",
        process_path=r"C:\Windows\System32\cmd.exe",
        classification="Malicious",
        action="Blocked",
        reason="High volume file modification pattern observed",
        command_line=r'cmd.exe /c rename D:\Shares\Operations\*.docx *.locked',
        event_target=r"D:\Shares\Operations",
        threat_attack_id="Data Encrypted for Impact",
        mitre_tags="T1486",
    )


# ============================================================
# FASES DEL EJERCICIO
# ============================================================

BASELINE_EVENTS = [
    fw_allow_traffic,
    dns_query_normal,
    proxy_access_normal,
    edr_login_success,
    edr_login_failure,
]

INITIAL_EVENTS = [
    dns_query_rare,
    proxy_large_post,
    fw_outbound_unusual,
    edr_linux_process_activity,
    edr_outbound_connection,
    edr_login_failure,
]

IDENTITY_EVENTS = [
    edr_privileged_logon,
    edr_group_change,
    edr_powershell_activity,
    edr_login_failure,
    fw_allow_traffic,
]

ESXI_EVENTS = [
    fw_deny_esxi,
    edr_privileged_logon,
    fw_allow_traffic,
]

BACKUP_EVENTS = [
    edr_backup_repository_access,
    edr_privileged_logon,
    fw_outbound_unusual,
    proxy_large_post,
]

IMPACT_EVENTS = [
    edr_file_rename_activity,
    edr_powershell_activity,
    edr_backup_repository_access,
    proxy_blocked,
    dns_nxdomain,
]

INCIDENT_EVENTS = (
    BASELINE_EVENTS
    + INITIAL_EVENTS
    + IDENTITY_EVENTS
    + ESXI_EVENTS
    + BACKUP_EVENTS
    + IMPACT_EVENTS
)

PHASES = {
    "baseline": BASELINE_EVENTS,
    "initial": INITIAL_EVENTS,
    "identity": IDENTITY_EVENTS,
    "esxi": ESXI_EVENTS,
    "backup": BACKUP_EVENTS,
    "impact": IMPACT_EVENTS,
    "incident": INCIDENT_EVENTS,
}

SEQUENCE = [
    ("baseline", 80, 1),
    ("initial", 120, 2),
    ("identity", 120, 2),
    ("esxi", 80, 2),
    ("backup", 100, 2),
    ("impact", 80, 2),
]


def choose_event(phase):
    if phase == "incident":
        if random.random() < 0.75:
            return random.choice(INCIDENT_EVENTS)()
        return random.choice(BASELINE_EVENTS)()

    return random.choice(PHASES[phase])()


# ============================================================
# ENVÍO SCAPY
# ============================================================

def send_syslog_scapy(source_key, message, iface=None, verbose=False):
    source = LOG_SOURCES[source_key]

    packet = (
        IP(src=source["ip"], dst=SIEM_IP)
        / UDP(sport=random.randint(20000, 65000), dport=SIEM_PORT)
        / Raw(load=message.encode("utf-8", errors="replace"))
    )

    send(packet, iface=iface, verbose=0)

    if verbose:
        print(f"{source['ip']} -> {SIEM_IP}:{SIEM_PORT} | {message}")


def send_phase(phase, count, eps, iface=None, verbose=False):
    delay = 1.0 / eps if eps > 0 else 0

    print("")
    print(f"[+] Fase: {phase}")
    print(f"[+] Eventos: {count}")
    print(f"[+] EPS: {eps}")

    for i in range(1, count + 1):
        source_key, message = choose_event(phase)
        source = LOG_SOURCES[source_key]

        send_syslog_scapy(
            source_key=source_key,
            message=message,
            iface=iface,
            verbose=verbose,
        )

        if not verbose:
            print(
                f"[{i}/{count}] "
                f"{source['hostname']} {source['ip']} -> {SIEM_IP}"
            )

        if delay > 0:
            time.sleep(delay)


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Operación Nodo Esencial - Envío consolidado a FortiSIEM con Scapy"
    )

    parser.add_argument(
        "--phase",
        choices=list(PHASES.keys()),
        default="incident",
        help="baseline, initial, identity, esxi, backup, impact, incident",
    )

    parser.add_argument("--count", type=int, default=100, help="Número de eventos")
    parser.add_argument("--eps", type=float, default=1.0, help="Eventos por segundo")
    parser.add_argument("--iface", default=None, help="Interfaz de salida, por ejemplo eth0")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--verbose", action="store_true")

    parser.add_argument(
        "--sequence",
        action="store_true",
        help="Ejecuta la secuencia completa del ejercicio",
    )

    parser.add_argument(
        "--pause",
        type=int,
        default=10,
        help="Pausa en segundos entre fases cuando se usa --sequence",
    )

    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    print("[+] Operación Nodo Esencial - Sender consolidado")
    print(f"[+] FortiSIEM destino: {SIEM_IP}:{SIEM_PORT}/udp")
    print("[+] Fuentes simuladas:")
    for key, source in LOG_SOURCES.items():
        print(f"    {source['hostname']:15s} {source['ip']}")
    print(f"[+] FortiEDR Organization: {FORTIEDR_ORG}")
    print(f"[+] FortiEDR OrganizationId: {FORTIEDR_ORG_ID}")

    if args.sequence:
        for idx, (phase, count, eps) in enumerate(SEQUENCE, start=1):
            print("")
            print("=" * 70)
            print(f"[+] Secuencia {idx}/{len(SEQUENCE)}")
            print("=" * 70)

            send_phase(
                phase=phase,
                count=count,
                eps=eps,
                iface=args.iface,
                verbose=args.verbose,
            )

            if idx < len(SEQUENCE) and args.pause > 0:
                print(f"[+] Pausa entre fases: {args.pause}s")
                time.sleep(args.pause)

        print("[OK] Secuencia completa finalizada")
        return

    send_phase(
        phase=args.phase,
        count=args.count,
        eps=args.eps,
        iface=args.iface,
        verbose=args.verbose,
    )

    print("[OK] Envío terminado")


if __name__ == "__main__":
    main()
