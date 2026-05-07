#!/usr/bin/env python3
from scapy.all import IP, UDP, Raw, send
from datetime import datetime
import argparse
import random
import time

# =========================
# CONFIG BASE
# =========================

DEFAULT_TARGET = "10.255.9.3"
DEFAULT_PORT = 514

FORTISWITCHES = [
    {
        "name": "MAD-CPD-FSW01",
        "serial": "FSW248EPTF230001",
        "src_ip": "10.255.9.21",
    },
    {
        "name": "MAD-CPD-FSW02",
        "serial": "FSW248EPTF230002",
        "src_ip": "10.255.9.22",
    },
    {
        "name": "MAD-ACC-FSW03",
        "serial": "FSW248EPTF230003",
        "src_ip": "10.255.9.23",
    },
    {
        "name": "BCN-ACC-FSW01",
        "serial": "FSW248EPTF230004",
        "src_ip": "10.255.9.24",
    },
]

SEVERITY_TO_PRI = {
    "critical": 186,  # local7.crit
    "warning": 188,   # local7.warning
    "notice": 189,    # local7.notice
    "info": 190,      # local7.info
}

PORTS = [
    "port3",
    "port8",
    "port10",
    "port12",
    "port18",
    "port21",
    "port22",
    "port24",
]

VLANS = [10, 20, 30, 40, 50, 999]

AUTHORIZED_MACS = [
    "70:4c:a5:22:18:90",
    "3c:52:82:91:aa:10",
    "ac:91:a1:44:20:11",
    "d8:bb:c1:10:90:aa",
]

UNAUTHORIZED_MACS = [
    "00:1b:17:aa:45:c0",
    "00:0c:29:de:ad:be",
    "00:50:56:8a:11:22",
    "08:00:27:13:37:01",
    "de:ad:be:ef:00:01",
]


def now_fields():
    now = datetime.now()
    date = now.strftime("%Y-%m-%d")
    hour = now.strftime("%H:%M:%S")
    eventtime = int(time.time() * 1_000_000_000)
    return date, hour, eventtime


def build_fortiswitch_log(sw, level, logid, fields):
    date, hour, eventtime = now_fields()

    base = {
        "date": date,
        "time": hour,
        "devname": sw["name"],
        "devid": sw["serial"],
        "type": "event",
        "subtype": "switch",
        "level": level,
        "logid": logid,
        "eventtime": eventtime,
        "switch_id": sw["serial"],
        "switch_name": sw["name"],
    }

    base.update(fields)

    parts = []
    for key, value in base.items():
        if isinstance(value, int):
            parts.append(f"{key}={value}")
        else:
            parts.append(f'{key}="{value}"')

    return " ".join(parts)


def send_syslog_scapy(target, dst_port, src_ip, payload, level="notice", sport=None, iface=None):
    pri = SEVERITY_TO_PRI.get(level, 189)

    # Fortinet-style syslog payload
    syslog_payload = f"<{pri}>{payload}"

    if sport is None:
        sport = random.randint(20000, 60999)

    packet = (
        IP(src=src_ip, dst=target)
        / UDP(sport=sport, dport=dst_port)
        / Raw(load=syslog_payload.encode())
    )

    send(packet, verbose=False, iface=iface)


def generate_event(sw, event_type):
    port = random.choice(PORTS)
    vlan = random.choice(VLANS)
    bad_mac = random.choice(UNAUTHORIZED_MACS)
    good_mac = random.choice(AUTHORIZED_MACS)

    if event_type == "sticky_learn":
        level = "notice"
        logid = "0100044510"
        fields = {
            "interface": port,
            "port": port,
            "vlan": vlan,
            "srcmac": good_mac,
            "action": "learn",
            "reason": "sticky-mac-learned",
            "msg": "Sticky MAC learned on secure access port",
        }

    elif event_type == "violation":
        level = "warning"
        logid = "0100044501"
        fields = {
            "interface": port,
            "port": port,
            "vlan": vlan,
            "srcmac": bad_mac,
            "action": "deny",
            "reason": "port-security-violation",
            "msg": "Port security violation detected: unauthorized MAC address on access port",
        }

    elif event_type == "mac_limit":
        level = "critical"
        logid = "0100044502"
        fields = {
            "interface": port,
            "port": port,
            "vlan": vlan,
            "srcmac": bad_mac,
            "action": "shutdown",
            "reason": "mac-limit-exceeded",
            "configured_mac_limit": 1,
            "learned_mac_count": random.randint(2, 5),
            "msg": "Port security MAC limit exceeded, port administratively disabled",
        }

    elif event_type == "quarantine":
        level = "warning"
        logid = "0100044503"
        fields = {
            "interface": port,
            "port": port,
            "vlan": 999,
            "srcmac": bad_mac,
            "action": "quarantine",
            "reason": "unauthorized-device",
            "quarantine_vlan": 999,
            "msg": "Unauthorized endpoint moved to quarantine VLAN by port security policy",
        }

    elif event_type == "sticky_mismatch":
        level = "warning"
        logid = "0100044511"
        fields = {
            "interface": port,
            "port": port,
            "vlan": vlan,
            "srcmac": bad_mac,
            "expected_mac": good_mac,
            "action": "deny",
            "reason": "sticky-mac-mismatch",
            "msg": "Port security violation: MAC address does not match configured sticky MAC",
        }

    elif event_type == "mac_flap":
        level = "warning"
        logid = "0100044520"
        fields = {
            "vlan": vlan,
            "srcmac": bad_mac,
            "old_interface": random.choice(PORTS),
            "new_interface": random.choice(PORTS),
            "action": "alert",
            "reason": "mac-flapping",
            "msg": "MAC address flapping detected between secure access ports",
        }

    elif event_type == "mac_spoofing":
        level = "critical"
        logid = "0100044521"
        fields = {
            "vlan": vlan,
            "srcmac": bad_mac,
            "interface": port,
            "action": "block",
            "reason": "possible-mac-spoofing",
            "msg": "Possible MAC spoofing detected, source MAC blocked by port security",
        }

    elif event_type == "dot1x_fail":
        level = "warning"
        logid = "0100044531"
        fields = {
            "interface": port,
            "port": port,
            "vlan": vlan,
            "srcmac": bad_mac,
            "user": "unknown",
            "auth_method": "MAB",
            "action": "deny",
            "reason": "authentication-failed",
            "msg": "MAC authentication bypass failed, endpoint denied by port security policy",
        }

    elif event_type == "port_disable":
        level = "critical"
        logid = "0100044540"
        fields = {
            "interface": port,
            "port": port,
            "action": "disable",
            "reason": "port-security-shutdown",
            "msg": "Secure port disabled due to repeated port security violations",
        }

    elif event_type == "admin_recovery":
        level = "notice"
        logid = "0100044541"
        fields = {
            "interface": port,
            "port": port,
            "action": "enable",
            "reason": "admin-recovery",
            "user": "netadmin",
            "srcip": "10.10.40.25",
            "msg": "Secure port manually re-enabled by administrator after port security violation",
        }

    else:
        level = "notice"
        logid = "0100044599"
        fields = {
            "interface": port,
            "port": port,
            "vlan": vlan,
            "srcmac": bad_mac,
            "action": "alert",
            "reason": "generic-port-security-event",
            "msg": "Generic FortiSwitch port security event",
        }

    payload = build_fortiswitch_log(sw, level, logid, fields)
    return level, payload


def run_random(args):
    event_types = [
        "sticky_learn",
        "violation",
        "mac_limit",
        "quarantine",
        "sticky_mismatch",
        "mac_flap",
        "mac_spoofing",
        "dot1x_fail",
        "port_disable",
        "admin_recovery",
    ]

    for i in range(args.count):
        sw = random.choice(FORTISWITCHES)
        event_type = random.choice(event_types)

        level, payload = generate_event(sw, event_type)

        src_ip = args.src_ip if args.src_ip else sw["src_ip"]

        send_syslog_scapy(
            target=args.target,
            dst_port=args.port,
            src_ip=src_ip,
            payload=payload,
            level=level,
            iface=args.iface,
        )

        print(f"[{i+1}/{args.count}] {src_ip} -> {args.target}:{args.port} {sw['name']} {event_type}")

        time.sleep(args.interval)


def run_campaign(args):
    sw = FORTISWITCHES[0]
    src_ip = args.src_ip if args.src_ip else sw["src_ip"]

    campaign = [
        "sticky_learn",
        "violation",
        "sticky_mismatch",
        "mac_limit",
        "quarantine",
        "port_disable",
        "admin_recovery",
    ]

    print(f"Campaña FortiSwitch Port Security desde {sw['name']} / {src_ip}")

    for step, event_type in enumerate(campaign, start=1):
        level, payload = generate_event(sw, event_type)

        send_syslog_scapy(
            target=args.target,
            dst_port=args.port,
            src_ip=src_ip,
            payload=payload,
            level=level,
            iface=args.iface,
        )

        print(f"[PASO {step}/{len(campaign)}] {event_type}")
        print(payload)
        print()

        if args.pause:
            input("Pulsa ENTER para lanzar el siguiente paso...")
        else:
            time.sleep(args.interval)


def main():
    parser = argparse.ArgumentParser(
        description="Generador de logs FortiSwitch port-security hacia FortiSIEM usando Scapy"
    )

    parser.add_argument("--target", default=DEFAULT_TARGET, help="IP de FortiSIEM Collector")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Puerto syslog UDP")
    parser.add_argument("--src-ip", help="IP origen spoofeada del FortiSwitch")
    parser.add_argument("--iface", help="Interfaz de salida, ejemplo: eth0")
    parser.add_argument("--count", type=int, default=20, help="Número de eventos")
    parser.add_argument("--interval", type=float, default=1.0, help="Segundos entre eventos")
    parser.add_argument("--campaign", action="store_true", help="Lanza una campaña coherente")
    parser.add_argument("--pause", action="store_true", help="Pausa entre pasos de campaña")

    args = parser.parse_args()

    if args.campaign:
        run_campaign(args)
    else:
        run_random(args)


if __name__ == "__main__":
    main()
