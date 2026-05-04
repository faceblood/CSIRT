#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Envío de logs genéricos a FortiSIEM usando Scapy con IP origen variable.

Uso en laboratorio controlado:
  sudo python3 send_scapy_syslog_fortisiem.py --siem 10.0.20.200 --count 200 --eps 2 --phase incident

Requisitos:
  pip install scapy

Notas:
- Solo UDP syslog.
- No genera archivos.
- No explota nada.
- La IP origen del paquete se fija con Scapy.
- Usa únicamente IPs internas del laboratorio.
"""

import argparse
import random
import time
from datetime import datetime

from scapy.all import IP, UDP, Raw, send


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
        "ip": "10.0.20.104",
    },
}

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

EXTERNAL_IPS = [
    "198.51.100.10",
    "198.51.100.22",
    "203.0.113.15",
    "203.0.113.44",
    "192.0.2.55",
]

USERS = [
    "svc_webapp",
    "svc_backup",
    "admin.local",
    "proveedor_soporte",
    "j.garcia",
    "m.lopez",
    "operador_noc",
]

DOMAINS_NORMAL = [
    "portal-servicios.age.local",
    "auth.corp.age.local",
    "backup.internal.age.local",
    "monitoring.internal.age.local",
    "updates.vendor.age.local",
    "repo.linux.age.local",
    "cdn.example.net",
    "api.example.net",
]

DOMAINS_RARE = [
    "cdn-update-check.example.net",
    "telemetry-sync.example.org",
    "storage-gateway.example.net",
    "fileshare-sync.example.org",
]


def syslog_ts():
    return datetime.now().strftime("%b %d %H:%M:%S")


def rfc3164(hostname: str, message: str, pri: int = 134) -> str:
    return f"<{pri}>{syslog_ts()} {hostname} {message}"


def random_server():
    name = random.choice(list(SERVERS.keys()))
    return name, SERVERS[name]


# ---------------------------------------------------------------------
# FIREWALL
# ---------------------------------------------------------------------

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

    return "fw", rfc3164("loggen-fw01", msg)


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

    return "fw", rfc3164("loggen-fw01", msg, pri=132)


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

    return "fw", rfc3164("loggen-fw01", msg)


# ---------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------

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

    return "dns", rfc3164("loggen-dns01", msg)


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

    return "dns", rfc3164("loggen-dns01", msg)


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

    return "dns", rfc3164("loggen-dns01", msg, pri=132)


# ---------------------------------------------------------------------
# PROXY
# ---------------------------------------------------------------------

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

    return "proxy", rfc3164("loggen-proxy01", msg)


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

    return "proxy", rfc3164("loggen-proxy01", msg, pri=132)


def proxy_blocked():
    src = random.choice(CLIENTS + [SERVERS["APP-LNX-01"]])
    domain = random.choice(DOMAINS_RARE)

    msg = (
        f'{int(time.time())}.{random.randint(100, 999)} '
        f'{random.randint(10, 500)} {src} TCP_DENIED/403 '
        f'{random.randint(100, 1000)} '
        f'CONNECT {domain}:443 - NONE/- text/html'
    )

    return "proxy", rfc3164("loggen-proxy01", msg, pri=132)


# ---------------------------------------------------------------------
# EDR / WINDOWS / LINUX GENERIC
# ---------------------------------------------------------------------

def linux_ssh_success():
    host = random.choice(["APP-LNX-01", "DB-LNX-01", "MON-LNX-01"])
    src = random.choice(CLIENTS + EXTERNAL_IPS)
    user = random.choice(["svc_webapp", "j.garcia", "proveedor_soporte"])

    msg = (
        f'{host} sshd[{random.randint(1000,9999)}]: '
        f'Accepted password for {user} from {src} '
        f'port {random.randint(20000,65000)} ssh2'
    )

    return "edr", rfc3164("loggen-edr01", msg)


def linux_ssh_failed():
    host = random.choice(["APP-LNX-01", "DB-LNX-01", "MON-LNX-01"])
    src = random.choice(CLIENTS + EXTERNAL_IPS)
    user = random.choice(USERS)

    msg = (
        f'{host} sshd[{random.randint(1000,9999)}]: '
        f'Failed password for {user} from {src} '
        f'port {random.randint(20000,65000)} ssh2'
    )

    return "edr", rfc3164("loggen-edr01", msg, pri=132)


def linux_process_generic():
    host = "APP-LNX-01"

    msg = (
        f'{host} auditd[{random.randint(1000,9999)}]: '
        f'type=EXECVE msg=audit({int(time.time())}.000:'
        f'{random.randint(1000,9999)}): '
        f'argc=3 a0="/usr/bin/python3" '
        f'a1="/tmp/worker.py" a2="--check" '
        f'uid=33 auid=33 ses={random.randint(1,20)}'
    )

    return "edr", rfc3164("loggen-edr01", msg, pri=132)


def windows_4624_success():
    host = random.choice(["DC-WIN-01", "JUMP-WIN-01", "FILE-WIN-01"])
    user = random.choice(USERS)
    src = random.choice(CLIENTS + [SERVERS["JUMP-WIN-01"]])
    logon_type = random.choice([3, 10])

    msg = (
        f'{host} WinEvtLog: Security: AUDIT_SUCCESS(4624): '
        f'Microsoft-Windows-Security-Auditing: '
        f'An account was successfully logged on. '
        f'Account Name: {user}; '
        f'Source Network Address: {src}; '
        f'Logon Type: {logon_type}; '
        f'Workstation Name: {host};'
    )

    return "edr", rfc3164("loggen-edr01", msg)


def windows_4625_failed():
    host = random.choice(["DC-WIN-01", "JUMP-WIN-01", "FILE-WIN-01"])
    user = random.choice(USERS)
    src = random.choice(CLIENTS + EXTERNAL_IPS)

    msg = (
        f'{host} WinEvtLog: Security: AUDIT_FAILURE(4625): '
        f'Microsoft-Windows-Security-Auditing: '
        f'An account failed to log on. '
        f'Account Name: {user}; '
        f'Source Network Address: {src}; '
        f'Logon Type: {random.choice([3, 10])}; '
        f'Failure Reason: Unknown user name or bad password;'
    )

    return "edr", rfc3164("loggen-edr01", msg, pri=132)


def windows_4672_privileged_logon():
    host = random.choice(["DC-WIN-01", "JUMP-WIN-01"])
    user = random.choice(["admin.local", "proveedor_soporte"])
    src = random.choice([SERVERS["JUMP-WIN-01"]] + CLIENTS)

    msg = (
        f'{host} WinEvtLog: Security: AUDIT_SUCCESS(4672): '
        f'Microsoft-Windows-Security-Auditing: '
        f'Special privileges assigned to new logon. '
        f'Account Name: {user}; '
        f'Source Network Address: {src}; '
        f'Privileges: SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege;'
    )

    return "edr", rfc3164("loggen-edr01", msg, pri=132)


def windows_group_change():
    host = "DC-WIN-01"
    user = random.choice(["admin.local", "proveedor_soporte"])

    msg = (
        f'{host} WinEvtLog: Security: AUDIT_SUCCESS(4728): '
        f'Microsoft-Windows-Security-Auditing: '
        f'A member was added to a security-enabled global group. '
        f'Subject Account Name: {user}; '
        f'Member Name: CN=svc_backup,CN=Users,DC=corp,DC=local; '
        f'Target Account Name: Domain Admins;'
    )

    return "edr", rfc3164("loggen-edr01", msg, pri=132)


def windows_service_created():
    host = random.choice(["JUMP-WIN-01", "FILE-WIN-01"])
    user = random.choice(["admin.local", "proveedor_soporte"])

    msg = (
        f'{host} WinEvtLog: System: INFORMATION(7045): '
        f'Service Control Manager: '
        f'A service was installed in the system. '
        f'Service Name: Windows Update Helper; '
        f'Service File Name: C:\\Windows\\Temp\\update-helper.exe; '
        f'Account Name: {user};'
    )

    return "edr", rfc3164("loggen-edr01", msg, pri=132)


def windows_file_activity():
    host = "FILE-WIN-01"
    user = random.choice(["svc_backup", "admin.local", "proveedor_soporte"])

    msg = (
        f'{host} WinEvtLog: Security: AUDIT_SUCCESS(4663): '
        f'Microsoft-Windows-Security-Auditing: '
        f'An attempt was made to access an object. '
        f'Account Name: {user}; '
        f'Object Name: D:\\Shares\\Operations\\report_{random.randint(1000,9999)}.docx; '
        f'Accesses: WriteData; '
        f'Process Name: C:\\Windows\\System32\\cmd.exe;'
    )

    return "edr", rfc3164("loggen-edr01", msg, pri=132)


BASELINE_EVENTS = [
    fw_allow_traffic,
    dns_query_normal,
    proxy_access_normal,
    linux_ssh_success,
    linux_ssh_failed,
    windows_4624_success,
    windows_4625_failed,
]

INITIAL_EVENTS = [
    dns_query_rare,
    proxy_large_post,
    linux_process_generic,
    fw_outbound_unusual,
]

IDENTITY_EVENTS = [
    windows_4625_failed,
    windows_4672_privileged_logon,
    windows_group_change,
    windows_4624_success,
]

ESXI_EVENTS = [
    fw_deny_esxi,
    windows_4672_privileged_logon,
    fw_allow_traffic,
]

BACKUP_EVENTS = [
    windows_4672_privileged_logon,
    windows_file_activity,
    fw_outbound_unusual,
]

INCIDENT_EVENTS = (
    BASELINE_EVENTS
    + INITIAL_EVENTS
    + IDENTITY_EVENTS
    + ESXI_EVENTS
    + BACKUP_EVENTS
    + [proxy_blocked, dns_nxdomain, windows_service_created]
)

PHASES = {
    "baseline": BASELINE_EVENTS,
    "initial": INITIAL_EVENTS,
    "identity": IDENTITY_EVENTS,
    "esxi": ESXI_EVENTS,
    "backup": BACKUP_EVENTS,
    "incident": INCIDENT_EVENTS,
}


def choose_event(phase):
    if phase == "incident":
        if random.random() < 0.65:
            return random.choice(INCIDENT_EVENTS)()
        return random.choice(BASELINE_EVENTS)()

    return random.choice(PHASES[phase])()


def send_syslog_scapy(siem_ip, siem_port, source_key, message, iface=None, verbose=False):
    src_ip = LOG_SOURCES[source_key]["ip"]

    packet = (
        IP(src=src_ip, dst=siem_ip)
        / UDP(sport=random.randint(20000, 65000), dport=siem_port)
        / Raw(load=message.encode("utf-8", errors="replace"))
    )

    send(packet, iface=iface, verbose=0)

    if verbose:
        print(f"{src_ip} -> {siem_ip}:{siem_port} | {message}")


def main():
    parser = argparse.ArgumentParser(
        description="Enviar logs syslog genéricos a FortiSIEM con Scapy e IP origen variable"
    )
    parser.add_argument("--siem", required=True, help="IP del FortiSIEM Collector/Supervisor")
    parser.add_argument("--port", type=int, default=514, help="Puerto syslog UDP")
    parser.add_argument("--count", type=int, default=100, help="Número de eventos")
    parser.add_argument("--eps", type=float, default=1.0, help="Eventos por segundo")
    parser.add_argument(
        "--phase",
        choices=list(PHASES.keys()),
        default="incident",
        help="baseline, initial, identity, esxi, backup, incident",
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Interfaz de salida, por ejemplo eth0. Opcional.",
    )
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    delay = 1.0 / args.eps if args.eps > 0 else 0

    print(f"[+] Enviando syslog UDP con Scapy a {args.siem}:{args.port}")
    print(f"[+] Fase: {args.phase}")
    print(f"[+] Eventos: {args.count}")
    print(f"[+] EPS: {args.eps}")
    print("[+] Reporting IPs simuladas:")
    for key, dev in LOG_SOURCES.items():
        print(f"    {dev['hostname']:15s} {dev['ip']}")

    for i in range(1, args.count + 1):
        source_key, message = choose_event(args.phase)
        send_syslog_scapy(
            siem_ip=args.siem,
            siem_port=args.port,
            source_key=source_key,
            message=message,
            iface=args.iface,
            verbose=args.verbose,
        )

        if not args.verbose:
            src_ip = LOG_SOURCES[source_key]["ip"]
            hostname = LOG_SOURCES[source_key]["hostname"]
            print(f"[{i}/{args.count}] {hostname} {src_ip}")

        if delay > 0:
            time.sleep(delay)

    print("[OK] Envío terminado")


if __name__ == "__main__":
    main()
