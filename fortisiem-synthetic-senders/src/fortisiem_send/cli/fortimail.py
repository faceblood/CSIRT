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
    p = argparse.ArgumentParser(description="Envía logs sintéticos FortiMail")
    add_repo_arg(p)
    add_network_args(p)
    add_throughput_args(p)
    add_syslog_reporting_ip_arg(p)
    p.add_argument("--src-ip-mode", default="random", type=parse_src_ip_mode)
    p.add_argument("--attacker-ip", default="", help="client_ip en plantilla y origen UDP")
    p.add_argument(
        "--user-samaccountname",
        default="",
        help="Usuario para el destinatario to= en plantillas (email desde users_ad.csv)",
    )
    p.add_argument("--c2-domain", default="", help="Dominio en from= (phishing); si vacío, sale de config")
    p.add_argument("--category", default="phishing", help="Categoría en plantillas")
    p.add_argument("--event-hint", default="")
    return p.parse_args()


def _main() -> int:
    ns = _parse()
    base = resolve_repo_root(ns)
    ctx = build_send_context(
        base,
        user_samaccountname=ns.user_samaccountname,
        attacker_ip=ns.attacker_ip,
        src_ip_mode=ns.src_ip_mode,
        c2_domain=ns.c2_domain,
        active_sources=frozenset({"fortimail"}),
        run_label="fortimail",
    )
    total = run_sender(
        base,
        source="fortimail",
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
