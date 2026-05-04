#!/usr/bin/env python3
from scapy.all import IP, UDP, Raw, send
from datetime import datetime
import random
import signal
import time

FORTISIEM_IP = "10.255.9.3"  # CAMBIA ESTO por la IP real del Collector/Supervisor
FORTISIEM_PORT = 514
INTERVAL_SECONDS = 60
MONITORING_IP = "10.255.0.10"

DEVICE_IPS = [
    "10.255.9.100", "10.255.9.69", "10.255.200.2", "10.255.10.6",
    "172.16.20.101", "172.16.20.102", "172.16.20.103",
    "10.0.20.102", "10.255.9.2", "10.0.20.103", "10.255.9.3", "10.0.20.104",
]

DEVICE_PROFILES = {
    "10.255.9.100": "linux",
    "10.255.9.69": "linux",
    "10.255.200.2": "linux",
    "10.255.10.6": "linux",

    # Mapeo solicitado
    "172.16.20.101": "fortigate",
    "172.16.20.102": "fortiproxy",
    "172.16.20.103": "linux",

    # Resto
    "10.0.20.102": "fortiproxy",
    "10.255.9.2": "fortigate",
    "10.0.20.103": "linux",
    "10.255.9.3": "fortigate",
    "10.0.20.104": "linux",
}

RUNNING = True

def stop_handler(signum, frame):
    global RUNNING
    RUNNING = False
    print("\n[!] Deteniendo FortiSIEM keepalive...")

signal.signal(signal.SIGINT, stop_handler)
signal.signal(signal.SIGTERM, stop_handler)

def syslog_ts():
    return datetime.now().strftime("%b %d %H:%M:%S")

def forti_date():
    return datetime.now().strftime("%Y-%m-%d")

def forti_time():
    return datetime.now().strftime("%H:%M:%S")

def epoch_ns():
    return f"{int(time.time())}000000000"

def hostname_from_ip(ip, prefix):
    return f"{prefix}-{ip.replace('.', '-')}"

def send_syslog(reporting_ip, hostname, message, pri="<134>"):
    payload = f"{pri}{syslog_ts()} {hostname} {message}"
    packet = IP(src=reporting_ip, dst=FORTISIEM_IP) / UDP(
        sport=random.randint(20000, 65000), dport=FORTISIEM_PORT
    ) / Raw(load=payload.encode())
    send(packet, verbose=False)

def linux_normal_log(ip):
    hostname = hostname_from_ip(ip, "linux")
    messages = [
        f"CRON[{random.randint(1000, 9999)}]: (root) CMD (/usr/lib/sa/sa1 1 1)",
        f"CRON[{random.randint(1000, 9999)}]: (root) CMD (/usr/sbin/logrotate /etc/logrotate.conf)",
        f"systemd[1]: Started Session {random.randint(1000, 9999)} of user root.",
        f"systemd[1]: Started Daily apt download activities.",
        f"sshd[{random.randint(1000, 9999)}]: Accepted publickey for monitoring from {MONITORING_IP} port {random.randint(30000, 65000)} ssh2",
        "sudo: monitoring : TTY=pts/0 ; PWD=/home/monitoring ; USER=root ; COMMAND=/usr/bin/uptime",
        "sudo: monitoring : TTY=pts/0 ; PWD=/home/monitoring ; USER=root ; COMMAND=/usr/bin/df -h",
        f"kernel: audit: type=USER_ACCT msg=audit({int(time.time())}.{random.randint(100,999)}:{random.randint(1000,9999)}): pid={random.randint(1000,9999)} uid=0 auid=4294967295 msg='op=PAM:accounting grantors=pam_unix acct=\"monitoring\" exe=\"/usr/sbin/sshd\" hostname={MONITORING_IP} addr={MONITORING_IP} terminal=ssh res=success'",
    ]
    return hostname, random.choice(messages), "<134>"

def fortigate_normal_log(ip):
    hostname = hostname_from_ip(ip, "FGT")
    sessionid = random.randint(100000, 999999)
    devid = f"FGVM{random.randint(100000000000, 999999999999)}"
    dstip, dstport, service, proto = random.choice([
        ("8.8.8.8", 53, "DNS", 17),
        ("1.1.1.1", 53, "DNS", 17),
        ("10.255.0.20", 123, "NTP", 17),
        ("10.255.0.30", 443, "HTTPS", 6),
    ])
    logs = [
        f'date={forti_date()} time={forti_time()} devname="{hostname}" devid="{devid}" eventtime={epoch_ns()} tz="+0100" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={ip} srcport={random.randint(30000,65000)} srcintf="lan" srcintfrole="lan" dstip={dstip} dstport={dstport} dstintf="wan1" dstintfrole="wan" sessionid={sessionid} proto={proto} action="accept" policyid=1 policytype="policy" service="{service}" trandisp="noop" sentbyte={random.randint(60,900)} rcvdbyte={random.randint(60,5000)} sentpkt={random.randint(1,12)} rcvdpkt={random.randint(1,12)} appcat="unscanned" msg="Normal {service} traffic keepalive"',
        f'date={forti_date()} time={forti_time()} devname="{hostname}" devid="{devid}" eventtime={epoch_ns()} tz="+0100" logid="0100032002" type="event" subtype="system" level="information" vd="root" logdesc="Admin login successful" user="monitoring" ui="ssh" action="login" status="success" msg="Administrator monitoring logged in successfully from {MONITORING_IP}"',
        f'date={forti_date()} time={forti_time()} devname="{hostname}" devid="{devid}" eventtime={epoch_ns()} tz="+0100" logid="0100032001" type="event" subtype="system" level="information" vd="root" logdesc="Configuration is in sync" status="success" msg="System keepalive normal status"',
    ]
    return hostname, random.choice(logs), "<189>"

def fortiproxy_normal_log(ip):
    hostname = hostname_from_ip(ip, "FPX")
    devid = f"FPXVM{random.randint(100000000000, 999999999999)}"
    url, host, dstip, dstport, service = random.choice([
        ("http://connectivity-check.ubuntu.com/", "connectivity-check.ubuntu.com", "91.189.91.48", 80, "HTTP"),
        ("http://example.com/healthcheck", "example.com", "93.184.216.34", 80, "HTTP"),
        ("https://repo.example.com/status", "repo.example.com", "93.184.216.34", 443, "HTTPS"),
        ("https://updates.example.com/check", "updates.example.com", "93.184.216.34", 443, "HTTPS"),
    ])
    log = (
        f'date={forti_date()} time={forti_time()} devname="{hostname}" devid="{devid}" '
        f'eventtime={epoch_ns()} tz="+0100" logid="0317013312" type="utm" subtype="webfilter" '
        f'eventtype="urlfilter" level="notice" vd="root" policyid=10 sessionid={random.randint(300000,399999)} '
        f'user="monitoring" srcip={ip} srcport={random.randint(30000,65000)} dstip={dstip} dstport={dstport} '
        f'proto=6 service="{service}" hostname="{host}" profile="default" action="passthrough" reqtype="direct" '
        f'url="{url}" sentbyte={random.randint(200,1200)} rcvdbyte={random.randint(1000,7000)} '
        f'direction="outgoing" msg="Normal proxy web activity keepalive"'
    )
    return hostname, log, "<189>"

def build_log_for_ip(ip):
    profile = DEVICE_PROFILES.get(ip, "linux")
    if profile == "fortigate":
        return fortigate_normal_log(ip)
    if profile == "fortiproxy":
        return fortiproxy_normal_log(ip)
    return linux_normal_log(ip)

def send_keepalive_round():
    print(f"\n[+] Ronda keepalive {datetime.now().isoformat(timespec='seconds')}")
    for ip in DEVICE_IPS:
        profile = DEVICE_PROFILES.get(ip, "linux")
        hostname, message, pri = build_log_for_ip(ip)
        send_syslog(ip, hostname, message, pri)
        print(f"    OK  {ip:15} profile={profile:10} hostname={hostname}")
        time.sleep(random.uniform(0.2, 0.8))

def main():
    print("[+] FortiSIEM Scapy Keepalive iniciado")
    print(f"[+] Destino: {FORTISIEM_IP}:{FORTISIEM_PORT}/UDP")
    print(f"[+] Intervalo: {INTERVAL_SECONDS} segundos")
    print("[+] Mapeo de perfiles:")
    for ip in DEVICE_IPS:
        print(f"    {ip:15} = {DEVICE_PROFILES.get(ip, 'linux')}")

    while RUNNING:
        start = time.time()
        send_keepalive_round()
        elapsed = time.time() - start
        sleep_time = max(1, INTERVAL_SECONDS - elapsed)
        print(f"[+] Próxima ronda en {int(sleep_time)} segundos")
        for _ in range(int(sleep_time)):
            if not RUNNING:
                break
            time.sleep(1)

    print("[+] Keepalive detenido correctamente.")

if __name__ == "__main__":
    main()
