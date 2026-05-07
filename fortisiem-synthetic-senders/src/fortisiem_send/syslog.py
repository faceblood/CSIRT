from __future__ import annotations

import random
from datetime import datetime


def format_rfc3164(hostname: str, message: str) -> str:
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return f"<134>{ts} {hostname} {message}"


def send_syslog_scapy(target: str, port: int, message: str, src_ip: str | None) -> None:
    try:
        from scapy.all import IP, Raw, UDP, send  # type: ignore
    except Exception as exc:
        raise RuntimeError("Scapy no instalado. Ejecuta: pip install scapy") from exc
    packet = IP(src=src_ip, dst=target) / UDP(
        sport=random.randint(1024, 65535),
        dport=port,
    ) / Raw(load=message.encode("utf-8"))
    send(packet, verbose=False)
