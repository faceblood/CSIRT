from __future__ import annotations

import random

from app.config import settings


def send_scapy_udp(*, reporting_ip: str, fortisiem_ip: str, port: int, payload: str) -> None:
    """Send raw syslog bytes via UDP with spoofed source IP (requires root)."""
    from scapy.all import IP, Raw, UDP, send

    pkt = (
        IP(src=reporting_ip, dst=fortisiem_ip)
        / UDP(sport=random.randint(20000, 65000), dport=port)
        / Raw(load=payload.encode("utf-8", errors="ignore"))
    )
    send(pkt, verbose=False)


def send_payload(
    *,
    reporting_ip: str,
    payload: str,
    fortisiem_ip: str | None = None,
    fortisiem_port: int | None = None,
    dry_run: bool = False,
) -> tuple[str, bool]:
    dst = fortisiem_ip or settings.fortisiem_ip
    port = fortisiem_port or settings.fortisiem_port
    if dry_run:
        return "dry_run", True
    send_scapy_udp(reporting_ip=reporting_ip, fortisiem_ip=dst, port=port, payload=payload)
    return "sent", True
