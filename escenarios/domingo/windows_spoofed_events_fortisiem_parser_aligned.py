#!/usr/bin/env python3
"""
Windows spoofed events -> FortiSIEM, aligned with existing WinSyslogParser

Este script genera eventos Windows en el formato que espera el parser subido:
  <PRI>May 03 12:00:00 HOST MSWinEventLog<TAB>1<TAB>Security<TAB>...

El parser actual reconoce "MSWinEventLog" y luego extrae:
  _agentSig = MSWinEventLog
  _mesgType = 1
  _OSModule = Security / Microsoft-Windows-Sysmon/Operational / etc.
  _id = Event ID
  eventSource
  _action = Success Audit / Failure Audit
  _body = resto

Para que parseen mejor:
  - Usa TABs entre campos del payload MSWinEventLog.
  - Usa IDs clásicos que tu parser trata explícitamente:
      529 = Failed logon
      540 = Successful network logon
      592 = Process created
      517 = Audit log cleared
  - Sysmon:
      1, 3, 11, 22 -> Win-Sysmon-1, Win-Sysmon-3, etc.

Uso:
  sudo apt update
  sudo apt install -y python3-scapy
  sudo python3 windows_spoofed_events_fortisiem_parser_aligned.py --fortisiem-ip 10.0.0.50 --once

Bucle:
  sudo python3 windows_spoofed_events_fortisiem_parser_aligned.py --fortisiem-ip 10.0.0.50 --loop --interval 60

Notas:
  - No ejecuta nada en Windows.
  - Solo envía syslog UDP sintético con IP origen spoofeada.
  - Para que genere incidentes, necesitas reglas sobre eventType:
      Win-Security-529
      Win-Security-540
      Win-Security-592
      Win-Security-517
      Win-Sysmon-1
      Win-Sysmon-3
      Win-Sysmon-11
      Win-Sysmon-22
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
    print("\n[!] Deteniendo simulador Windows alineado a WinSyslogParser...")


signal.signal(signal.SIGINT, stop_handler)
signal.signal(signal.SIGTERM, stop_handler)


def syslog_ts():
    return datetime.now().strftime("%b %d %H:%M:%S")


def win_time_parts():
    """
    Tu parser espera:
      <_dayName:gPatWord> <_mon:gPatMon> <_day:gPatDay> <_time:gPatTime> <_year:gPatYear>
    Ejemplo:
      Sun May 03 12:45:01 2026
    """
    return datetime.now().strftime("%a %b %d %H:%M:%S %Y")


def xml_time():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def send_syslog(args, msg_payload):
    """
    FortiSIEM verá args.reporting_ip como Reporting IP si tu red permite UDP spoofing.

    Importante:
    - El parser subido tiene una primera rama que espera syslog PRI + fecha + host + MSWinEventLog.
    - Por eso aquí construimos el raw completo así:
        <134>May 03 12:00:00 WIN-LAB-01 MSWinEventLog<TAB>1<TAB>Security...
    """
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
    Payload esperado por el WinSyslogParser:

      MSWinEventLog
      1
      Security
      seqNum
      Sun May 03 12:45:01 2026
      eventId
      eventSource
      account
      accountType
      action
      body

    Donde body debe comenzar preferiblemente con:
      COMPUTER CATEGORY MESSAGE...
    porque los ejemplos del parser lo hacen así.
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
        f"{computer} {category} {body}",
    ]
    return "\t".join(fields)


def event_failed_logon_529(args):
    """
    Parser branch:
      when $_id IN 529..537
      keys:
        User Name:
        Domain:
        Logon ID:
        Logon Type:
        Source Network Address:
        Source Port:
        Workstation Name:
    eventType esperado: Win-Security-529
    """
    user = random.choice(["administrator", "admin", "svc_backup", args.user])
    logon_id = f"(0x0,0x{random.randint(100000, 0xFFFFFF):X})"

    body = (
        "Logon Failure: "
        f"Reason: Unknown user name or bad password "
        f"User Name: {user} "
        f"Domain: {args.domain} "
        f"Logon Type: 3 "
        f"Logon Process: NtLmSsp "
        f"Authentication Package: NTLM "
        f"Workstation Name: WIN-REMOTE "
        f"Logon ID: {logon_id} "
        f"Source Network Address: {args.attacker_ip} "
        f"Source Port: {random.randint(40000, 65000)} "
        "exercise_id=SOC-DRILL-WIN-2026"
    )

    return mswineventlog_payload(
        "Security",
        529,
        "Security",
        "SYSTEM",
        "User",
        "Failure Audit",
        args.hostname,
        "Logon/Logoff",
        body,
    )


def event_success_network_logon_540(args):
    """
    Parser branch:
      when $_id = 540
      keys:
        User Name:
        Domain:
        Logon ID:
        Logon Type:
        Source Network Address:
        Source Port:
        Workstation Name:
    eventType esperado: Win-Security-540
    """
    logon_id = f"(0x0,0x{random.randint(100000, 0xFFFFFF):X})"

    body = (
        "Successful Network Logon: "
        f"User Name: {args.user} "
        f"Domain: {args.domain} "
        f"Logon ID: {logon_id} "
        f"Logon Type: 3 "
        f"Logon Process: Kerberos "
        f"Authentication Package: Kerberos "
        f"Workstation Name: WIN-REMOTE "
        f"Source Network Address: {args.attacker_ip} "
        f"Source Port: {random.randint(40000, 65000)} "
        "exercise_id=SOC-DRILL-WIN-2026"
    )

    return mswineventlog_payload(
        "Security",
        540,
        "Security",
        args.user,
        "User",
        "Success Audit",
        args.hostname,
        "Logon/Logoff",
        body,
    )


def event_process_created_592(args):
    """
    Parser branch:
      when $_id IN 592,593
      keys:
        User Name:
        Domain:
        Logon ID:
        Image File Name:
        Process ID:
        Creator Process ID:
    eventType esperado: Win-Security-592
    """
    proc = random.choice([
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\mshta.exe",
        r"C:\Windows\System32\rundll32.exe",
        r"C:\Users\Public\Documents\AdobeSync\AdobeUpdate.exe",
    ])

    body = (
        "A new process has been created: "
        f"New Process ID: {random.randint(1000, 9000)} "
        f"Image File Name: {proc} "
        f"Creator Process ID: {random.randint(1000, 9000)} "
        f"User Name: {args.user} "
        f"Domain: {args.domain} "
        f"Logon ID: (0x0,0x{random.randint(100000, 0xFFFFFF):X}) "
        "Command Line: powershell.exe -NoProfile -EncodedCommand <redacted> "
        "exercise_id=SOC-DRILL-WIN-2026"
    )

    return mswineventlog_payload(
        "Security",
        592,
        "Security",
        args.user,
        "User",
        "Success Audit",
        args.hostname,
        "Detailed Tracking",
        body,
    )


def event_audit_log_cleared_517(args):
    """
    Parser branch:
      when $_id = 517
      keys:
        Client User Name:
        Client Domain:
        Client Logon ID:
    eventType esperado: Win-Security-517
    """
    body = (
        "The audit log was cleared "
        f"Client User Name: {args.user} "
        f"Client Domain: {args.domain} "
        f"Client Logon ID: (0x0, 0x{random.randint(100000, 0xFFFFFF):X}) "
        "exercise_id=SOC-DRILL-WIN-2026"
    )

    return mswineventlog_payload(
        "Security",
        517,
        "Security",
        "SYSTEM",
        "User",
        "Success Audit",
        args.hostname,
        "System Event",
        body,
    )


def sysmon_payload(args, event_id, category, body):
    """
    Parser branch:
      $_OSModule = Microsoft-Windows-Sysmon/Operational
      eventType = Win-Sysmon-<id>
      Then it maps key-values:
        CommandLine:
        CurrentDirectory:
        DestinationHostname:
        DestinationIp:
        DestinationPort:
        Image:
        ParentCommandLine:
        ParentImage:
        SourceHostname:
        SourceIp:
        SourcePort:
        TargetFilename:
        User:
    """
    return mswineventlog_payload(
        "Microsoft-Windows-Sysmon/Operational",
        event_id,
        "Microsoft-Windows-Sysmon",
        args.user,
        "User",
        "Information",
        args.hostname,
        category,
        body,
    )


def event_sysmon_1_process_create(args):
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


def event_sysmon_3_network(args):
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
        f"DestinationHostname: update-checkin-cdn.evil-example.com "
        f"DestinationIp: {dst_ip} "
        "DestinationPort: 443 "
        "exercise_id=SOC-DRILL-WIN-2026"
    )
    return sysmon_payload(args, 3, "Network Connection", body)


def event_sysmon_11_file(args):
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


def event_sysmon_22_dns(args):
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

    # Brute-force style: old Windows failed logon IDs
    for _ in range(args.failed_logons):
        events.append(event_failed_logon_529(args))

    # Success after failures
    events.append(event_success_network_logon_540(args))

    # Process creation and audit clear
    events.append(event_process_created_592(args))

    # Sysmon activity
    events.append(event_sysmon_1_process_create(args))
    events.append(event_sysmon_11_file(args))
    events.append(event_sysmon_22_dns(args))

    for _ in range(args.c2_events):
        events.append(event_sysmon_3_network(args))

    # Audit cleared
    events.append(event_audit_log_cleared_517(args))

    return events


def send_round(args):
    events = build_campaign(args)
    print(f"\n[+] Enviando {len(events)} eventos Windows alineados a WinSyslogParser")

    for i, event in enumerate(events, start=1):
        send_syslog(args, event)
        print(f"    OK {i:03d}/{len(events)} reporting_ip={args.reporting_ip} host={args.hostname}")
        time.sleep(random.uniform(args.min_delay, args.max_delay))


def parse_args():
    p = argparse.ArgumentParser(description="Windows spoofed Syslog events aligned to FortiSIEM WinSyslogParser")
    p.add_argument("--fortisiem-ip", required=True, help="IP del FortiSIEM Collector/Supervisor")
    p.add_argument("--port", type=int, default=514, help="Puerto syslog destino")
    p.add_argument("--reporting-ip", default="10.0.20.105", help="IP origen spoofeada / Reporting IP")
    p.add_argument("--hostname", default="WIN-LAB-01", help="Hostname Windows simulado")
    p.add_argument("--windows-ip", default="10.0.10.30", help="IP interna del Windows simulado para SourceIp")
    p.add_argument("--domain", default="CORP", help="Dominio Windows")
    p.add_argument("--user", default="j.garcia", help="Usuario víctima")
    p.add_argument("--attacker-ip", default="185.231.88.45", help="IP atacante simulada")
    p.add_argument("--failed-logons", type=int, default=12, help="Número de eventos 529 por ronda")
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
    print("Evento 529 de test para Test Parser:")
    print(f"{args.pri}{syslog_ts()} {args.hostname} {event_failed_logon_529(args)}")
    print()
    print("Evento Sysmon 3 de test para Test Parser:")
    print(f"{args.pri}{syslog_ts()} {args.hostname} {event_sysmon_3_network(args)}")


def main():
    args = parse_args()

    print("[+] Windows spoofed events alineado a WinSyslogParser")
    print(f"[+] FortiSIEM: {args.fortisiem_ip}:{args.port}/UDP")
    print(f"[+] Reporting IP spoofeada: {args.reporting_ip}")
    print(f"[+] Hostname: {args.hostname}")
    print("[+] EventTypes esperados: Win-Security-529, Win-Security-540, Win-Security-592, Win-Security-517, Win-Sysmon-1/3/11/22")

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

