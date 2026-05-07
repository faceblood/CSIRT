from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..constants import DEFAULT_PORT, DEFAULT_RATE, DEFAULT_TARGET
from ..ip_utils import parse_syslog_src_ip


def resolve_repo_root(ns: argparse.Namespace) -> Path:
    cfg = getattr(ns, "config_dir", None)
    if cfg is not None:
        p = Path(cfg).resolve()
        if p.name == "config":
            return p.parent
        return p
    if getattr(ns, "repo_root", None):
        return Path(ns.repo_root).resolve()
    return Path.cwd().resolve()


def add_repo_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Directorio que contiene config/ y log_repository/ (por defecto: directorio actual)",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="Ruta a la carpeta config/ del proyecto; la raíz del repo se toma como su directorio padre",
    )


def add_network_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", default=DEFAULT_TARGET, help="IP del collector syslog")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--syslog-hostname", default="localhost", help="Hostname en prefijo RFC3164")


def add_throughput_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE, help="Eventos por segundo (aprox.)")
    parser.add_argument("--dry-run", action="store_true", help="Solo imprime el mensaje, no envía UDP")


def add_syslog_reporting_ip_arg(parser: argparse.ArgumentParser) -> None:
    """Origen L3 del UDP syslog; en FortiSIEM suele alinearse con reporting IP / IP vista por el collector."""
    parser.add_argument(
        "--syslog-src-ip",
        default="",
        type=parse_syslog_src_ip,
        metavar="IPv4",
        help=(
            "Reporting IP: IPv4 origen del paquete syslog hacia --target (no cambia placeholders del cuerpo; "
            "usa --attacker-ip u otros flags según la fuente). Si se omite, origen UDP = src_ip del render"
        ),
    )


def cli_main_wrapper(entry_fn) -> int:
    try:
        return entry_fn()
    except KeyboardInterrupt:
        print("\nInterrumpido por usuario.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
