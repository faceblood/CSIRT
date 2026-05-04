#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Operación Nodo Esencial - Sender realista para FortiSIEM

Destino FortiSIEM:
  10.255.9.202:514/UDP

Reporting IPs simuladas:
  loggen-fw01     10.0.20.101   -> FortiGate-like traffic logs
  loggen-dns01    10.0.20.102   -> BIND-like DNS logs
  loggen-proxy01  10.0.20.103   -> Squid-like proxy logs
  loggen-edr01    10.0.20.104   -> FortiEDR CEF logs

Requisitos:
  pip install scapy

Uso:
  sudo python3 nodo_esencial_sender_realistic.py --phase incident --count 300 --eps 3
  sudo python3 nodo_esencial_sender_realistic.py --sequence
"""

import argparse
import random
import time
from datetime import datetime, timezone
from scapy.all import IP, UDP, Raw, send


# ============================================================
# CONFIG
# ============================================================

SIEM_IP = "10.255.9.3"
SIEM_PORT = 514

LOG_SOURCES = {
    "fw": {"hostname": "loggen-fw01", "ip": "10.0.20.101"},
    "dns": {"hostname": "loggen-dns01", "ip": "10.0.20.102"},
    "proxy": {"hostname": "loggen-proxy01", "ip": "10.0.20.103"},
    "edr": {"hostname": "loggen-edr01", "ip": "10.0.20.104"},
}

FORTIEDR_ORG = "1"
FORTIEDR_ORG_ID = "1"


# ============================================================
# ENTORNO
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

NORMAL_DOMAINS = [
    "portal-servicios.local",
    "auth.corp.local",
    "backup.internal.local",
    "monitoring.internal.local",
    "updates.vendor.local",
    "repo.linux.local",
    "cdn.example.net",
    "api.example.net",
]

RARE_DOMAINS = [
    "cdn-update-check.example.net",
    "telemetry-sync.example.org",
    "storage-gateway.example.net",
    "fileshare-sync.example.org",
]


# ============================================================
# HELPERS
# ============================================================

def syslog_ts():
    return datetime.now().strftime("%b %d %H:%M:%S")


def iso_date():
    return datetime.now().strftime("%Y-%m-%d")


def iso_time():
    return datetime.now().strftime("%H:%M:%S")


def epoch_ns():
    return int(time.time() * 1_000_000_000)


def edr_time():
    return datetime.now(timezone.utc).strftime("%d-%m-%Y, %H:%M:%S")


def rfc3164(hostname, message, pri=134):
    return f"<{pri}>{syslog_ts()} {hostname} {message}"


def cef_escape(value):
    value = str(value)
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def random_server():
    host = random.choice(list(SERVERS.keys()))
    return host, SERVERS[host]


# ============================================================
# FORTIGATE-LIKE FIREWALL LOGS
# ============================================================

def fw_traffic_accept():
    src = random.choice(CLIENTS)
    dst_host, dst_ip = random_server()
    dst_port = random.choice([53, 80, 88, 389, 443, 445, 3389, 8080])
    proto = 6 if dst_port not in [53, 88] else random.choice([6, 17])
    service = {
        53: "DNS",
        80: "HTTP",
        88: "KERBEROS",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
        8080: "HTTP-Alt",
    }[dst_port]

    msg = (
        f'date={iso_date()} time={iso_time()} devname="loggen-fw01" devid="FGT60FTK00000001" '
        f'eventtime={epoch_ns()} tz="+0200" logid="0000000013" type="traffic" subtype="forward" '
        f'level="notice" vd="root" srcip={src} srcport={random.randint(20000, 65000)} '
        f'srcintf="port2" srcintfrole="lan" dstip={dst_ip} dstport={dst_port} '
        f'dstintf="port3" dstintfrole="server" srccountry="Reserved" dstcountry="Reserved" '
        f'sessionid={random.randint(100000, 999999)} proto={proto} action="accept" policyid=10 '
        f'policytype="policy" service="{service}" trandisp="noop" duration={random.randint(1, 300)} '
        f'sentbyte={random.randint(500, 80000)} rcvdbyte={random.randint(500, 80000)} '
        f'sentpkt={random.randint(3, 100)} rcvdpkt={random.randint(3, 100)} appcat="unscanned" '
        f'dstname="{dst_host}"'
    )
    return "fw", rfc3164("loggen-fw01", msg, pri=134)


def fw_esxi_admin_denied():
    src = random.choice([SERVERS["JUMP-WIN-01"]] + CLIENTS)

    msg = (
        f'date={iso_date()} time={iso_time()} devname="loggen-fw01" devid="FGT60FTK00000001" '
        f'eventtime={epoch_ns()} tz="+0200" logid="0000000013" type="traffic" subtype="forward" '
        f'level="warning" vd="root" srcip={src} srcport={random.randint(20000, 65000)} '
        f'srcintf="port2" srcintfrole="lan" dstip={SERVERS["ESXI-HOST-01"]} dstport=443 '
        f'dstintf="port4" dstintfrole="dmz" srccountry="Reserved" dstcountry="Reserved" '
        f'sessionid={random.randint(100000, 999999)} proto=6 action="deny" policyid=90 '
        f'policytype="policy" service="HTTPS" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0 '
        f'sentpkt=0 rcvdpkt=0 appcat="unscanned" dstname="ESXI-HOST-01" msg="Denied by firewall policy"'
    )
    return "fw", rfc3164("loggen-fw01", msg, pri=132)


def fw_large_outbound_https():
    src = random.choice([SERVERS["APP-LNX-01"], SERVERS["DB-LNX-01"], SERVERS["JUMP-WIN-01"]])
    dst = random.choice(EXTERNAL_IPS)

    msg = (
        f'date={iso_date()} time={iso_time()} devname="loggen-fw01" devid="FGT60FTK00000001" '
        f'eventtime={epoch_ns()} tz="+0200" logid="0000000013" type="traffic" subtype="forward" '
        f'level="notice" vd="root" srcip={src} srcport={random.randint(20000, 65000)} '
        f'srcintf="port3" srcintfrole="server" dstip={dst} dstport=443 dstintf="wan1" '
        f'dstintfrole="wan" srccountry="Reserved" dstcountry="Reserved" '
        f'sessionid={random.randint(100000, 999999)} proto=6 action="accept" policyid=20 '
        f'policytype="policy" service="HTTPS" trandisp="snat" duration={random.randint(20, 900)} '
        f'sentbyte={random.randint(5000000, 60000000)} rcvdbyte={random.randint(1000, 20000)} '
        f'sentpkt={random.randint(2000, 9000)} rcvdpkt={random.randint(20, 200)} appcat="unscanned"'
    )
    return "fw", rfc3164("loggen-fw01", msg, pri=134)


# ============================================================
# BIND-LIKE DNS LOGS
# ============================================================

def dns_normal_query():
    src = random.choice(CLIENTS + list(SERVERS.values()))
    domain = random.choice(NORMAL_DOMAINS)
    msg = (
        f'named[{random.randint(1000, 9999)}]: client @{random.randint(100000,999999)} '
        f'{src}#{random.randint(20000,65000)} ({domain}): query: {domain} IN A +E(0)K '
        f'(10.0.20.102)'
    )
    return "dns", rfc3164("loggen-dns01", msg, pri=134)


def dns_rare_query():
    src = random.choice([SERVERS["APP-LNX-01"], SERVERS["DB-LNX-01"], SERVERS["JUMP-WIN-01"]])
    domain = random.choice(RARE_DOMAINS)
    msg = (
        f'named[{random.randint(1000, 9999)}]: client @{random.randint(100000,999999)} '
        f'{src}#{random.randint(20000,65000)} ({domain}): query: {domain} IN A +E(0)K '
        f'(10.0.20.102)'
    )
    return "dns", rfc3164("loggen-dns01", msg, pri=132)


def dns_nxdomain_burst():
    src = random.choice([SERVERS["APP-LNX-01"], SERVERS["JUMP-WIN-01"]] + CLIENTS)
    domain = f"{random.randint(10000,99999)}-{random.choice(RARE_DOMAINS)}"
    msg = (
        f'named[{random.randint(1000, 9999)}]: client @{random.randint(100000,999999)} '
        f'{src}#{random.randint(20000,65000)} ({domain}): query failed (NXDOMAIN) for {domain}/IN/A '
        f'at query.c:7852'
    )
    return "dns", rfc3164("loggen-dns01", msg, pri=132)


# ============================================================
# SQUID-LIKE PROXY LOGS
# ============================================================

def proxy_normal_access():
    src = random.choice(CLIENTS)
    domain = random.choice(NORMAL_DOMAINS)
    status = random.choice(["TCP_TUNNEL/200", "TCP_MISS/200", "TCP_HIT/200"])

    msg = (
        f'{int(time.time())}.{random.randint(100,999)} {random.randint(20,1200)} '
        f'{src} {status} {random.randint(500, 250000)} '
        f'{random.choice(["CONNECT", "GET", "POST"])} https://{domain}/ '
        f'- HIER_DIRECT/{random.choice(EXTERNAL_IPS)} -'
    )
    return "proxy", rfc3164("loggen-proxy01", msg, pri=134)


def proxy_large_post():
    src = random.choice([SERVERS["APP-LNX-01"], SERVERS["DB-LNX-01"]])
    domain = random.choice(RARE_DOMAINS)

    msg = (
        f'{int(time.time())}.{random.randint(100,999)} {random.randint(800,4000)} '
        f'{src} TCP_MISS/200 {random.randint(6000000, 50000000)} '
        f'POST https://{domain}/api/upload '
        f'- HIER_DIRECT/{random.choice(EXTERNAL_IPS)} application/octet-stream'
    )
    return "proxy", rfc3164("loggen-proxy01", msg, pri=132)


def proxy_denied_rare():
    src = random.choice([SERVERS["APP-LNX-01"]] + CLIENTS)
    domain = random.choice(RARE_DOMAINS)

    msg = (
        f'{int(time.time())}.{random.randint(100,999)} {random.randint(10,700)} '
        f'{src} TCP_DENIED/403 {random.randint(200,2000)} '
        f'CONNECT {domain}:443 - NONE/- text/html'
    )
    return "proxy", rfc3164("loggen-proxy01", msg, pri=132)


# ============================================================
# FORTIEDR CEF LOGS
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
        f"{k}={cef_escape(v)}"
        for k, v in fields.items()
        if v != ""
    )

    return "edr", rfc3164("loggen-edr01", header + extension, pri=133)


def edr_baseline_logon():
    host = random.choice(["DC-WIN-01", "JUMP-WIN-01", "FILE-WIN-01"])
    return fortiedr_cef(
        eventid=random.randint(100000, 199999),
        name="Logon Activity",
        severity=3,
        host=host,
        user=random.choice(USERS),
        process_name="lsass.exe",
        process_path=r"C:\Windows\System32\lsass.exe",
        classification="Logon",
        action="Detected",
        reason="User logon activity observed",
        src_ip=random.choice(CLIENTS),
        event_target=host,
    )


def edr_failed_logon():
    host = random.choice(["DC-WIN-01", "JUMP-WIN-01", "FILE-WIN-01"])
    return fortiedr_cef(
        eventid=random.randint(200000, 299999),
        name="Failed Logon Activity",
        severity=4,
        host=host,
        user=random.choice(USERS),
        process_name="lsass.exe",
        process_path=r"C:\Windows\System32\lsass.exe",
        classification="Logon",
        action="Detected",
        reason="Failed user logon activity observed",
        src_ip=random.choice(CLIENTS + EXTERNAL_IPS),
        event_target=host,
    )


def edr_privileged_logon():
    host = random.choice(["DC-WIN-01", "JUMP-WIN-01"])
    return fortiedr_cef(
        eventid=random.randint(300000, 399999),
        name="Privileged Logon",
        severity=7,
        host=host,
        user=random.choice(["admin.local", "proveedor_soporte"]),
        process_name="lsass.exe",
        process_path=r"C:\Windows\System32\lsass.exe",
        classification="Suspicious",
        action="Detected",
        reason="Privileged account logon observed outside expected pattern",
        src_ip=random.choice([SERVERS["JUMP-WIN-01"]] + CLIENTS),
        event_target=host,
        threat_attack_id="Valid Accounts",
        mitre_tags="T1078",
    )


def edr_powershell():
    host = random.choice(["JUMP-WIN-01", "FILE-WIN-01"])
    return fortiedr_cef(
        eventid=random.randint(400000, 499999),
        name="Suspicious PowerShell",
        severity=8,
        host=host,
        user=random.choice(["admin.local", "proveedor_soporte"]),
        process_name="powershell.exe",
        process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        classification="Suspicious",
        action="Detected",
        reason="PowerShell execution observed with encoded command line",
        command_line=r"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <redacted>",
        event_target=host,
        threat_attack_id="Command and Scripting Interpreter",
        mitre_tags="T1059.001",
    )


def edr_group_change():
    return fortiedr_cef(
        eventid=random.randint(500000, 599999),
        name="Privileged Group Modification",
        severity=8,
        host="DC-WIN-01",
        user=random.choice(["admin.local", "proveedor_soporte"]),
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


def edr_linux_web_process():
    return fortiedr_cef(
        eventid=random.randint(600000, 699999),
        name="Suspicious Linux Process",
        severity=8,
        host="APP-LNX-01",
        user="svc_webapp",
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
    remote_ip = random.choice(EXTERNAL_IPS)

    if host in ["APP-LNX-01", "DB-LNX-01"]:
        process_name = "nginx"
        process_path = "/usr/sbin/nginx"
        user = "svc_webapp"
    else:
        process_name = "svchost.exe"
        process_path = r"C:\Windows\System32\svchost.exe"
        user = random.choice(["admin.local", "proveedor_soporte"])

    return fortiedr_cef(
        eventid=random.randint(700000, 799999),
        name="Suspicious Network Connection",
        severity=7,
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


def edr_backup_enum():
    return fortiedr_cef(
        eventid=random.randint(800000, 899999),
        name="Backup Repository Enumeration",
        severity=8,
        host="BACKUP-WIN-01",
        user="svc_backup",
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


def edr_ransomware_block():
    return fortiedr_cef(
        eventid=random.randint(900000, 999999),
        name="Ransomware",
        severity=10,
        host="FILE-WIN-01",
        user=random.choice(["svc_backup", "admin.local", "proveedor_soporte"]),
        process_name="cmd.exe",
        process_path=r"C:\Windows\System32\cmd.exe",
        classification="Malicious",
        action="Blocked",
        reason="Mass file modification and rename pattern blocked",
        command_line=r'cmd.exe /c rename D:\Shares\Operations\*.docx *.locked',
        event_target=r"D:\Shares\Operations",
        threat_attack_id="Data Encrypted for Impact",
        mitre_tags="T1486",
        count=random.randint(15, 50),
    )


# ============================================================
# FASES
# ============================================================

BASELINE_EVENTS = [
    fw_traffic_accept,
    dns_normal_query,
    proxy_normal_access,
    edr_baseline_logon,
    edr_failed_logon,
]

INITIAL_EVENTS = [
    dns_rare_query,
    proxy_large_post,
    fw_large_outbound_https,
    edr_linux_web_process,
    edr_outbound_connection,
    edr_failed_logon,
]

IDENTITY_EVENTS = [
    edr_privileged_logon,
    edr_group_change,
    edr_powershell,
    edr_failed_logon,
    fw_traffic_accept,
]

ESXI_EVENTS = [
    fw_esxi_admin_denied,
    edr_privileged_logon,
    fw_traffic_accept,
]

BACKUP_EVENTS = [
    edr_backup_enum,
    edr_privileged_logon,
    fw_large_outbound_https,
    proxy_large_post,
]

IMPACT_EVENTS = [
    edr_ransomware_block,
    edr_powershell,
    edr_backup_enum,
    proxy_denied_rare,
    dns_nxdomain_burst,
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
    ("impact", 120, 3),
]


def choose_event(phase):
    if phase == "incident":
        if random.random() < 0.80:
            return random.choice(INCIDENT_EVENTS)()
        return random.choice(BASELINE_EVENTS)()
    return random.choice(PHASES[phase])()


# ============================================================
# ENVÍO
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

    print(f"\n[+] Phase={phase} count={count} eps={eps}")

    for i in range(1, count + 1):
        source_key, message = choose_event(phase)
        source = LOG_SOURCES[source_key]

        send_syslog_scapy(source_key, message, iface=iface, verbose=verbose)

        if not verbose:
            print(f"[{i}/{count}] {source['hostname']} {source['ip']} -> {SIEM_IP}")

        if delay > 0:
            time.sleep(delay)


def main():
    parser = argparse.ArgumentParser(
        description="Operación Nodo Esencial - realistic syslog sender to FortiSIEM"
    )
    parser.add_argument("--phase", choices=list(PHASES.keys()), default="incident")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--eps", type=float, default=1.0)
    parser.add_argument("--iface", default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--sequence", action="store_true")
    parser.add_argument("--pause", type=int, default=10)

    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    print("[+] Operación Nodo Esencial - realistic sender")
    print(f"[+] FortiSIEM: {SIEM_IP}:{SIEM_PORT}/udp")
    for src in LOG_SOURCES.values():
        print(f"    {src['hostname']:15s} {src['ip']}")

    if args.sequence:
        for index, (phase, count, eps) in enumerate(SEQUENCE, start=1):
            print("\n" + "=" * 70)
            print(f"[+] Sequence {index}/{len(SEQUENCE)}: {phase}")
            print("=" * 70)

            send_phase(phase, count, eps, iface=args.iface, verbose=args.verbose)

            if index < len(SEQUENCE) and args.pause > 0:
                print(f"[+] Pausa {args.pause}s")
                time.sleep(args.pause)

        print("[OK] Secuencia completa finalizada")
        return

    send_phase(args.phase, args.count, args.eps, iface=args.iface, verbose=args.verbose)
    print("[OK] Envío terminado")


if __name__ == "__main__":
    main()
