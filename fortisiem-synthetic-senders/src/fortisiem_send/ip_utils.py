from __future__ import annotations

import argparse
import ipaddress
import random

from .models import Asset


def parse_syslog_src_ip(value: str) -> str:
    """IPv4 for UDP packet source toward the SIEM; empty = use render src_ip."""
    if value is None or not str(value).strip():
        return ""
    candidate = str(value).strip()
    try:
        ipaddress.IPv4Address(candidate)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "syslog-src-ip debe ser una IPv4 válida (o omitir el flag)"
        ) from exc
    return candidate


def parse_src_ip_mode(value: str) -> str:
    candidate = value.strip()
    if candidate in {"random", "asset"}:
        return candidate
    try:
        ipaddress.IPv4Address(candidate)
        return candidate
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "src-ip-mode debe ser 'random', 'asset' o una IPv4 valida"
        ) from exc


def choose_attacker_ip(mode: str, assets: list[Asset]) -> str:
    if mode == "asset":
        return random.choice(assets).ip
    if mode != "random":
        return mode
    first = random.randint(11, 223)
    return f"{first}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
