#!/usr/bin/env python3
from scapy.all import IP, UDP, Raw, send
from datetime import datetime
from pathlib import Path
import argparse
import csv
import random
import sys
import time


# =========================
# CONFIG BASE
# =========================

DEFAULT_TARGET = "10.255.9.3"
DEFAULT_PORT = 514
DEFAULT_INVENTORY_CSV = "fortiswitch_inventory_200.csv"

SEVERITY_TO_PRI = {
    "critical": 186,  # local7.crit
    "warning": 188,   # local7.warning
    "notice": 189,    # local7.notice
    "info": 190,      # local7.info
}

EVENT_TYPES = [
    "sticky_learn",
    "violation",
    "mac_limit",
    "quarantine",
    "sticky_mismatch",
    "mac_flap",
    "mac_spoofing",
    "dot1x_success",
    "dot1x_fail",
    "port_disable",
    "admin_recovery",
    "config_change",
]

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

VLANS = [10, 20, 30, 40, 50]

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


# =========================
# INVENTARIO CSV
# =========================

def load_switch_inventory(csv_path):
    path = Path(csv_path)

    if not path.exists():
        raise FileNotFoundError(
            f"No existe el CSV de inventario: {csv_path}\n"
            f"Pon el fichero en el mismo directorio o usa --inventory-csv /ruta/fichero.csv"
        )

    switches = []

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        required = {"name", "serial", "src_ip"}
        found = set(reader.fieldnames or [])

        missing = required - found
        if missing:
            raise ValueError(
                f"El CSV debe tener las columnas: name,serial,src_ip. "
                f"Faltan: {', '.join(sorted(missing))}"
            )

        for row_num, row in enumerate(reader, start=2):
            name = (row.get("name") or "").strip()
            serial = (row.get("serial") or "").strip()
            src_ip = (row.get("src_ip") or "").strip()

            if not name and not serial and not src_ip:
                continue

            if not name or not serial or not src_ip:
                raise ValueError(
                    f"Fila {row_num} incompleta. Debe tener name, serial y src_ip."
                )

            switches.append(
                {
                    "name": name,
                    "serial": serial,
                    "src_ip": src_ip,
                }
            )

    if not switches:
        raise ValueError(f"El CSV {csv_path} no contiene switches válidos.")

    return switches


def select_switch(args, switches):
    if args.switch_name:
        for sw in switches:
            if sw["name"].lower() == args.switch_name.lower():
                return sw

        raise ValueError(f"No existe switch con name={args.switch_name}")

    if args.switch_index < 1 or args.switch_index > len(switches):
        raise ValueError(
            f"--switch-index debe estar entre 1 y {len(switches)}"
        )

    return switches[args.switch_index - 1]


# =========================
# FUNCIONES BASE
# =========================

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
    syslog_payload = f"<{pri}>{payload}"

    if sport is None:
        sport = random.randint(20000, 60999)

    packet = (
        IP(src=src_ip, dst=target)
        / UDP(sport=sport, dport=dst_port)
        / Raw(load=syslog_payload.encode())
    )

    send(packet, verbose=False, iface=iface)


# =========================
# GENERADOR DE EVENTOS
# =========================

def generate_event(sw, event_type, context=None):
    """
    context permite que una campaña mantenga coherencia:
    mismo puerto, vlan, MAC buena y MAC mala en todos los pasos.
    """
    context = context or {}

    port = context.get("port", random.choice(PORTS))
    vlan = context.get("vlan", random.choice(VLANS))
    bad_mac = context.get("bad_mac", random.choice(UNAUTHORIZED_MACS))
    good_mac = context.get("good_mac", random.choice(AUTHORIZED_MACS))

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

        old_port = context.get("old_port", random.choice(PORTS))
        new_port = context.get(
            "new_port",
            random.choice([p for p in PORTS if p != old_port])
        )

        fields = {
            "vlan": vlan,
            "srcmac": bad_mac,
            "old_interface": old_port,
            "new_interface": new_port,
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
            "port": port,
            "action": "block",
            "reason": "possible-mac-spoofing",
            "msg": "Possible MAC spoofing detected, source MAC blocked by port security",
        }

    elif event_type == "dot1x_success":
        level = "notice"
        logid = "0100044530"
        fields = {
            "interface": port,
            "port": port,
            "vlan": vlan,
            "srcmac": good_mac,
            "user": "j.garcia",
            "auth_method": "802.1x",
            "action": "accept",
            "reason": "authentication-success",
            "msg": "802.1X authentication successful on secure port",
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

    elif event_type == "config_change":
        level = "notice"
        logid = "0100044550"
        fields = {
            "interface": port,
            "port": port,
            "user": "netadmin",
            "srcip": "10.10.40.25",
            "action": "config-change",
            "reason": "port-security-policy-update",
            "msg": "Port security configuration changed: mac-limit=1 violation-action=shutdown quarantine-vlan=999",
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


# =========================
# MODOS DE EJECUCIÓN
# =========================

def run_single_event(args, switches):
    sw = select_switch(args, switches)
    src_ip = args.src_ip if args.src_ip else sw["src_ip"]

    context = {
        "port": args.port_name or random.choice(PORTS),
        "vlan": args.vlan or random.choice(VLANS),
        "bad_mac": args.bad_mac or random.choice(UNAUTHORIZED_MACS),
        "good_mac": args.good_mac or random.choice(AUTHORIZED_MACS),
    }

    level, payload = generate_event(sw, args.event, context=context)

    send_syslog_scapy(
        target=args.target,
        dst_port=args.syslog_port,
        src_ip=src_ip,
        payload=payload,
        level=level,
        iface=args.iface,
    )

    print(f"[OK] Enviado evento concreto: {args.event}")
    print(f"switch={sw['name']} serial={sw['serial']}")
    print(f"{src_ip} -> {args.target}:{args.syslog_port}")
    print(payload)


def run_random(args, switches):
    for i in range(args.count):
        sw = random.choice(switches)
        event_type = random.choice(EVENT_TYPES)
        src_ip = args.src_ip if args.src_ip else sw["src_ip"]

        level, payload = generate_event(sw, event_type)

        send_syslog_scapy(
            target=args.target,
            dst_port=args.syslog_port,
            src_ip=src_ip,
            payload=payload,
            level=level,
            iface=args.iface,
        )

        print(
            f"[{i + 1}/{args.count}] "
            f"{src_ip} -> {args.target}:{args.syslog_port} "
            f"{sw['name']} {event_type}"
        )

        if args.print_payload:
            print(payload)
            print()

        time.sleep(args.interval)


def run_campaign(args, switches):
    sw = select_switch(args, switches)
    src_ip = args.src_ip if args.src_ip else sw["src_ip"]

    context = {
        "port": args.port_name or "port12",
        "vlan": args.vlan or 20,
        "bad_mac": args.bad_mac or "00:1b:17:aa:45:c0",
        "good_mac": args.good_mac or "70:4c:a5:22:18:90",
        "old_port": "port3",
        "new_port": "port8",
    }

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
    print(f"serial={sw['serial']} port={context['port']} vlan={context['vlan']}")
    print(f"good_mac={context['good_mac']} bad_mac={context['bad_mac']}")
    print()

    for step, event_type in enumerate(campaign, start=1):
        level, payload = generate_event(sw, event_type, context=context)

        send_syslog_scapy(
            target=args.target,
            dst_port=args.syslog_port,
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


# =========================
# MAIN
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="Generador de logs FortiSwitch port-security hacia FortiSIEM usando Scapy y CSV"
    )

    parser.add_argument(
        "--inventory-csv",
        default=DEFAULT_INVENTORY_CSV,
        help="CSV de inventario con columnas: name,serial,src_ip",
    )

    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help="IP de FortiSIEM Collector",
    )

    parser.add_argument(
        "--syslog-port",
        type=int,
        default=DEFAULT_PORT,
        help="Puerto syslog UDP destino",
    )

    parser.add_argument(
        "--src-ip",
        help="Sobrescribe la IP origen del CSV. Si no se usa, toma src_ip del switch seleccionado.",
    )

    parser.add_argument(
        "--iface",
        help="Interfaz de salida, ejemplo: eth0, ens160, ens192",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Número de eventos en modo aleatorio",
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Segundos entre eventos",
    )

    parser.add_argument(
        "--campaign",
        action="store_true",
        help="Lanza una campaña coherente de port-security",
    )

    parser.add_argument(
        "--pause",
        action="store_true",
        help="Pausa entre pasos de campaña",
    )

    parser.add_argument(
        "--event",
        choices=EVENT_TYPES,
        help="Envía un único evento concreto de port-security",
    )

    parser.add_argument(
        "--switch-index",
        type=int,
        default=1,
        help="Índice del FortiSwitch dentro del CSV. Empieza en 1.",
    )

    parser.add_argument(
        "--switch-name",
        help="Nombre exacto del FortiSwitch dentro del CSV, ejemplo: MAD-CPD-FSW57",
    )

    parser.add_argument(
        "--list-switches",
        action="store_true",
        help="Muestra el inventario cargado desde CSV y sale",
    )

    parser.add_argument(
        "--print-payload",
        action="store_true",
        help="Muestra el payload completo de cada evento aleatorio",
    )

    parser.add_argument(
        "--port-name",
        help="Puerto FortiSwitch a usar en --event o --campaign, ejemplo: port12",
    )

    parser.add_argument(
        "--vlan",
        type=int,
        help="VLAN a usar en --event o --campaign",
    )

    parser.add_argument(
        "--bad-mac",
        help="MAC no autorizada para eventos de violación",
    )

    parser.add_argument(
        "--good-mac",
        help="MAC autorizada para eventos sticky/dot1x",
    )

    args = parser.parse_args()

    try:
        switches = load_switch_inventory(args.inventory_csv)

        if args.list_switches:
            for idx, sw in enumerate(switches, start=1):
                print(f"{idx},{sw['name']},{sw['serial']},{sw['src_ip']}")
            return

        if args.event:
            run_single_event(args, switches)
        elif args.campaign:
            run_campaign(args, switches)
        else:
            run_random(args, switches)

    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
