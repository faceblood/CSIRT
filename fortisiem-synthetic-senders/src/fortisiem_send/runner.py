from __future__ import annotations

import time
from pathlib import Path

from .loaders import load_templates
from .models import RenderStep, SendContext, Template
from .render import render
from .syslog import format_rfc3164, send_syslog_scapy
from .templates import select_template


def run_sender(
    base: Path,
    *,
    source: str,
    category: str,
    event_hint: str,
    ctx: SendContext,
    templates: list[Template] | None = None,
    step: RenderStep | None = None,
    target: str,
    port: int,
    syslog_hostname: str,
    count: int,
    rate: int,
    dry_run: bool,
    syslog_src_ip: str = "",
) -> int:
    if templates is None:
        templates = load_templates(base)
    if step is None:
        step = RenderStep()
    rate_sleep = 1.0 / max(1, rate)
    sent = 0
    while sent < count:
        template = select_template(templates, source, category, event_hint)
        if template is None:
            raise RuntimeError(
                f"No hay plantillas para source={source!r} category={category!r}. "
                "Revisa log_repository/ o ajusta --category / --event-hint."
            )
        raw, src_ip = render(template.template, ctx, source, step)
        wire = format_rfc3164(syslog_hostname, raw)
        print(raw)
        if not dry_run:
            packet_src = syslog_src_ip.strip() if syslog_src_ip.strip() else src_ip
            if isinstance(packet_src, str) and not packet_src.strip():
                packet_src = None
            send_syslog_scapy(target, port, wire, src_ip=packet_src)
        sent += 1
        time.sleep(rate_sleep)
    return sent
