from __future__ import annotations

import argparse

from ..ip_utils import parse_src_ip_mode
from ..loaders import build_send_context
from ..runner import run_sender
from .common import (
    add_network_args,
    add_repo_arg,
    add_syslog_reporting_ip_arg,
    add_throughput_args,
    cli_main_wrapper,
    resolve_repo_root,
)


def _parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Envía logs sintéticos Windows (EVTX-like text)")
    add_repo_arg(p)
    add_network_args(p)
    add_throughput_args(p)
    add_syslog_reporting_ip_arg(p)
    p.add_argument("--src-ip-mode", default="random", type=parse_src_ip_mode)
    p.add_argument("--attacker-ip", default="", help="IP en plantilla (p.ej. 4625) y origen UDP")
    p.add_argument("--user-samaccountname", default="", help="Usuario en users_ad.csv")
    p.add_argument("--endpoint-ip", default="")
    p.add_argument("--initial-asset-ip", default="")
    p.add_argument("--initial-asset-hostname", default="")
    p.add_argument("--hostname", default="", help="HostName en el texto del evento")
    p.add_argument("--lateral-asset-ip", default="", help="Otro equipo Windows en assets.csv")
    p.add_argument(
        "--category",
        default="powershell",
        help="Categoría (powershell, security, process, ransomware, ...)",
    )
    p.add_argument("--event-hint", default="")
    return p.parse_args()


def _main() -> int:
    ns = _parse()
    base = resolve_repo_root(ns)
    ctx = build_send_context(
        base,
        user_samaccountname=ns.user_samaccountname,
        endpoint_ip=ns.endpoint_ip,
        initial_asset_ip=ns.initial_asset_ip,
        initial_asset_hostname=ns.initial_asset_hostname,
        hostname=ns.hostname,
        lateral_asset_ip=ns.lateral_asset_ip,
        attacker_ip=ns.attacker_ip,
        src_ip_mode=ns.src_ip_mode,
        active_sources=frozenset({"windows"}),
        run_label="windows",
    )
    total = run_sender(
        base,
        source="windows",
        category=ns.category,
        event_hint=ns.event_hint,
        ctx=ctx,
        target=ns.target,
        port=ns.port,
        syslog_hostname=ns.syslog_hostname,
        count=max(1, ns.count),
        rate=max(1, ns.rate),
        dry_run=ns.dry_run,
        syslog_src_ip=ns.syslog_src_ip,
    )
    print(f"Done. run_id={ctx.run_id} events={total}")
    return 0


def main() -> int:
    return cli_main_wrapper(_main)


if __name__ == "__main__":
    raise SystemExit(main())
