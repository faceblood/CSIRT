#!/usr/bin/env python3
"""
Standalone FortiSwitch event sender using Scapy.

Purpose:
- Send synthetic FortiSwitch syslog-like UDP packets to a FortiSIEM collector.
- Keep this script isolated from existing projects.

Notes:
- Root/admin privileges are typically required for raw packet sending (Scapy send()).
- For parser compatibility, messages include device_id and log_id fields.
"""

from __future__ import annotations

import argparse
import datetime as dt
import random
import sys
import time
from typing import Dict

from scapy.all import IP, UDP, Raw, send  # type: ignore


EVENT_TEMPLATES: Dict[str, Dict[str, str]] = {
    # _id 32001 => FortiSwitch-Sys-Admin-login-success
    "admin_login_success": {
        "log_id": "0103032001",
        "type": "event",
        "subtype": "system",
        "pri": "information",
        "status": "success",
        "msg": "Administrator login successful",
    },
    # _id 32002 => FortiSwitch-Sys-Admin-login-failed
    "admin_login_failed": {
        "log_id": "0103032002",
        "type": "event",
        "subtype": "system",
        "pri": "warning",
        "status": "failed",
        "reason": "invalid_password",
        "msg": "Administrator login failed",
    },
    # _id 01401 => FortiSwitch-Link-port-down
    "port_down": {
        "log_id": "0100014001",
        "type": "event",
        "subtype": "link",
        "pri": "warning",
        "msg": "FS-148F-001 switch port port12 has gone down",
    },
    # _id 08150 => STP Root Guard: Superior BPDUs received
    "stp_root_guard": {
        "log_id": "010008150",
        "type": "event",
        "subtype": "stp",
        "pri": "warning",
        "msg": "STP Root Guard: Superior BPDUs received on port24 (STP instance 1)",
    },
}


def build_body(template_name: str, device_id: str, devname: str, srcip: str, user: str) -> str:
    now = dt.datetime.now()
    current_date = now.strftime("%Y-%m-%d")
    current_time = now.strftime("%H:%M:%S")

    fields = {
        "date": current_date,
        "time": current_time,
        "devname": devname,
        "device_id": device_id,
        "srcip": srcip,
        "user": user,
        "vd": "root",
    }
    fields.update(EVENT_TEMPLATES[template_name])

    # Keep key=value style because your parser uses collectFieldsByKeyValuePair
    ordered = [
        "date",
        "time",
        "devname",
        "device_id",
        "log_id",
        "type",
        "subtype",
        "pri",
        "user",
        "srcip",
        "status",
        "reason",
        "vd",
        "msg",
    ]
    chunks = []
    for key in ordered:
        value = fields.get(key)
        if value:
            chunks.append(f'{key}="{value}"')
    return " ".join(chunks)


def send_event(dst_ip: str, dst_port: int, src_ip: str, body: str, delay: float, count: int) -> None:
    for idx in range(count):
        sport = random.randint(20000, 65000)
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dst_port) / Raw(load=body.encode("utf-8"))
        send(packet, verbose=False)
        print(f"[{idx + 1}/{count}] sent -> {dst_ip}:{dst_port} | {body}")
        if idx < count - 1 and delay > 0:
            time.sleep(delay)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send synthetic FortiSwitch events to FortiSIEM using Scapy."
    )
    parser.add_argument("--dst-ip", required=True, help="FortiSIEM collector IP")
    parser.add_argument("--dst-port", type=int, default=514, help="Collector syslog UDP port (default: 514)")
    parser.add_argument(
        "--src-ip",
        default="10.10.10.50",
        help="Source IP to put in IP header (default: 10.10.10.50)",
    )
    parser.add_argument(
        "--template",
        choices=sorted(EVENT_TEMPLATES.keys()),
        default="admin_login_failed",
        help="Event template to send",
    )
    parser.add_argument("--device-id", default="FS-148F-001", help='device_id field (default: "FS-148F-001")')
    parser.add_argument("--devname", default="FORTISW-CORE-01", help="devname field")
    parser.add_argument("--user", default="admin", help="user field")
    parser.add_argument("--actor-ip", default="192.168.10.25", help="srcip field inside log body")
    parser.add_argument("--count", type=int, default=20, help="How many packets to send")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay seconds between packets")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    body = build_body(
        template_name=args.template,
        device_id=args.device_id,
        devname=args.devname,
        srcip=args.actor_ip,
        user=args.user,
    )
    print("Sending FortiSwitch synthetic events with Scapy")
    print(f"Template : {args.template}")
    print(f"Target   : {args.dst_ip}:{args.dst_port}")
    print(f"IP src   : {args.src_ip}")
    print("-" * 60)

    try:
        send_event(
            dst_ip=args.dst_ip,
            dst_port=args.dst_port,
            src_ip=args.src_ip,
            body=body,
            delay=args.delay,
            count=args.count,
        )
    except PermissionError:
        print("Permission denied: run with sudo/admin privileges for raw packet sending.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped by user.")
        return 130

    print("-" * 60)
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
