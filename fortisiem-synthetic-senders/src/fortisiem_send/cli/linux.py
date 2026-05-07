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
    p = argparse.ArgumentParser(description="Envía logs sintéticos Linux (syslog text)")
    add_repo_arg(p)
    add_network_args(p)
    add_throughput_args(p)
    add_syslog_reporting_ip_arg(p)
    p.add_argument("--src-ip-mode", default="random", type=parse_src_ip_mode)
    p.add_argument("--attacker-ip", default="", help="IP en plantilla y origen UDP")
    p.add_argument(
        "--user-samaccountname",
        default="",
        help="Usuario en el mensaje; si lo pones, debe existir en config/users_ad.csv",
    )
    p.add_argument("--linux-asset-ip", default="", help="Equipo Linux en assets.csv")
    p.add_argument(
        "--category",
        default="ssh",
        help="Categoría (ssh, auth, sudo, ...)",
    )
    p.add_argument("--event-hint", default="")
    return p.parse_args()


def _main() -> int:
    ns = _parse()
    base = resolve_repo_root(ns)
    ctx = build_send_context(
        base,
        user_samaccountname=ns.user_samaccountname,
        linux_asset_ip=ns.linux_asset_ip,
        attacker_ip=ns.attacker_ip,
        src_ip_mode=ns.src_ip_mode,
        active_sources=frozenset({"linux"}),
        run_label="linux",
    )
    total = run_sender(
        base,
        source="linux",
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
