from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.campaigns.chat_builder import build_campaign_from_prompt
from app.sources.registry import all_sources

router = APIRouter(prefix="/api/campaign-chat", tags=["campaign-chat"])


class CampaignChatBody(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)


def _catalog() -> dict[str, set[str]]:
    """
    Returns { source_id: {event_type_id, ...} }.
    """
    out: dict[str, set[str]] = {}
    for src in all_sources():
        out[src.id] = {et.id for et in src.list_event_types()}
    return out


@router.post("")
def campaign_chat(body: CampaignChatBody):
    base = build_campaign_from_prompt(body.prompt)
    cat = _catalog()

    errors: list[dict] = []
    adjusted_steps: list[dict] = []
    corrections: list[dict] = []

    def substitute_unknown_event_type(*, step_index: int, src: str, ev: str, st: dict) -> dict | None:
        """
        Best-effort substitution when a source exists but the requested event_type doesn't.
        Returns a single corrected step dict or None.
        """
        available = cat.get(src)
        if not available:
            return None

        # 1) Heuristic: pick a same-kind event if possible.
        ev_l = ev.lower()
        preferred_by_keyword: list[tuple[str, list[str]]] = [
            ("dns", ["dns_query"]),
            ("traffic", ["traffic_accept", "traffic_deny"]),
            ("deny", ["traffic_deny", "access_block", "webfilter_block"]),
            ("allow", ["traffic_accept", "access_allow", "webfilter_passthrough"]),
            ("phish", ["phishing_detected"]),
            ("spam", ["spam_detected"]),
            ("virus", ["virus_detected"]),
            ("dlp", ["dlp_violation", "policy_match"]),
            ("ransom", ["ransomware"]),
            ("c2", ["c2"]),
            ("discover", ["discovery"]),
            ("lateral", ["lateral_movement"]),
            ("ssh", ["sshd_failed", "sshd_accepted"]),
            ("sudo", ["sudo"]),
            ("audit", ["audit_execve"]),
        ]
        for kw, candidates in preferred_by_keyword:
            if kw in ev_l:
                for c in candidates:
                    if c in available:
                        fixed = dict(st)
                        fixed["event_type"] = c
                        corrections.append(
                            {
                                "step": step_index,
                                "type": "substitute_event_type",
                                "source_id": src,
                                "from": ev,
                                "to": c,
                                "note": f"event_type not available for {src}; substituted by keyword '{kw}'",
                            }
                        )
                        return fixed

        # 2) Source-specific defaults (safe fallbacks)
        defaults: dict[str, list[str]] = {
            "fortigate": ["dns_query", "traffic_accept", "traffic_deny", "event_admin_login"],
            "windows": ["4688", "4625", "4624", "sysmon_1", "sysmon_3", "sysmon_11", "sysmon_22"],
            "linux": ["sshd_failed", "audit_execve", "sudo", "cron", "systemd_service"],
            "fortiedr": ["suspicious_process", "c2", "discovery", "lateral_movement", "ransomware"],
            "fortimail": ["phishing_detected", "spam_detected", "virus_detected", "email_received", "dlp_violation"],
            "fortiproxy": ["webfilter_block", "webfilter_passthrough", "baseline_webfilter"],
            "fortiweb": ["attack_sqli", "attack_xss", "bot_detection", "access_block", "access_allow"],
            "fortidlp": ["policy_match", "cloud_upload", "pii_detected", "usb_write"],
            "active_directory": ["4768", "4769", "4771", "4776", "4720", "4728", "4740"],
        }
        for c in defaults.get(src, []):
            if c in available:
                fixed = dict(st)
                fixed["event_type"] = c
                corrections.append(
                    {
                        "step": step_index,
                        "type": "substitute_event_type",
                        "source_id": src,
                        "from": ev,
                        "to": c,
                        "note": "event_type not available; substituted with a default valid event_type",
                    }
                )
                return fixed

        # 3) Last resort: deterministic pick
        c = sorted(available)[0]
        fixed = dict(st)
        fixed["event_type"] = c
        corrections.append(
            {
                "step": step_index,
                "type": "substitute_event_type",
                "source_id": src,
                "from": ev,
                "to": c,
                "note": "event_type not available; substituted with first available event_type",
            }
        )
        return fixed

    def substitute_unknown_source(*, step_index: int, src: str, ev: str, st: dict) -> list[dict]:
        """
        Best-effort substitution when a requested source isn't available.
        Returns a list of replacement steps (already in step-dict shape).
        """
        # Only implement substitutions we know are requested often.
        if src == "vmware":
            # Replace VMware "impact" with an equivalent SOC-visible pattern:
            # - FortiGate deny/traffic anomalies
            # - Windows process creation (PowerShell)
            # - FortiEDR ransomware / discovery / suspicious process
            repl: list[dict] = []
            base_count = int(st.get("count") or 10)
            base_delay = int(st.get("delay_s") or 2)

            if "fortigate" in cat and "traffic_deny" in cat["fortigate"]:
                repl.append(
                    {
                        "tactic": st.get("tactic") or "Impact",
                        "technique": st.get("technique") or "N/A",
                        "source_id": "fortigate",
                        "event_type": "traffic_deny",
                        "count": max(4, int(base_count * 1.2)),
                        "delay_s": max(1, base_delay),
                        "params_json": "{}",
                    }
                )
            if "windows" in cat and "4688" in cat["windows"]:
                repl.append(
                    {
                        "tactic": st.get("tactic") or "Impact",
                        "technique": "T1059.001",
                        "source_id": "windows",
                        "event_type": "4688",
                        "count": max(4, int(base_count * 0.8)),
                        "delay_s": max(1, base_delay),
                        "params_json": '{"process":"powershell.exe"}',
                    }
                )
            if "fortiedr" in cat:
                if "ransomware" in cat["fortiedr"]:
                    repl.append(
                        {
                            "tactic": st.get("tactic") or "Impact",
                            "technique": "T1486",
                            "source_id": "fortiedr",
                            "event_type": "ransomware",
                            "count": max(3, int(base_count * 0.6)),
                            "delay_s": max(1, base_delay),
                            "params_json": "{}",
                        }
                    )
                elif "suspicious_process" in cat["fortiedr"]:
                    repl.append(
                        {
                            "tactic": st.get("tactic") or "Impact",
                            "technique": "T1059.001",
                            "source_id": "fortiedr",
                            "event_type": "suspicious_process",
                            "count": max(3, int(base_count * 0.6)),
                            "delay_s": max(1, base_delay),
                            "params_json": "{}",
                        }
                    )

            if repl:
                corrections.append(
                    {
                        "step": step_index,
                        "type": "substitute_source",
                        "from": {"source_id": src, "event_type": ev},
                        "to": [{"source_id": r["source_id"], "event_type": r["event_type"]} for r in repl],
                        "note": "vmware not available; substituted with fortigate/windows/fortiedr equivalents",
                    }
                )
            return repl

        return []

    for i, st in enumerate(base.get("steps", []), start=1):
        src = st.get("source_id")
        ev = st.get("event_type")

        if not isinstance(src, str) or not src:
            errors.append({"step": i, "type": "invalid_step", "detail": "Missing source_id"})
            continue
        if not isinstance(ev, str) or not ev:
            errors.append({"step": i, "type": "invalid_step", "detail": "Missing event_type"})
            continue

        if src not in cat:
            # Attempt autocorrection before failing the step.
            repl = substitute_unknown_source(step_index=i, src=src, ev=ev, st=st)
            if repl:
                adjusted_steps.extend(repl)
                continue

            errors.append(
                {
                    "step": i,
                    "type": "unknown_source",
                    "source_id": src,
                    "event_type": ev,
                    "detail": f"Source not available: {src}",
                    "available_sources": sorted(cat.keys()),
                }
            )
            continue

        if ev not in cat[src]:
            fixed = substitute_unknown_event_type(step_index=i, src=src, ev=ev, st=st)
            if fixed is not None:
                adjusted_steps.append(fixed)
                continue

            errors.append(
                {
                    "step": i,
                    "type": "unknown_event_type",
                    "source_id": src,
                    "event_type": ev,
                    "detail": f"Event type not available for {src}: {ev}",
                    "available_event_types": sorted(cat[src]),
                }
            )
            continue

        adjusted_steps.append(st)

    adjusted = dict(base)
    adjusted["steps"] = adjusted_steps
    adjusted["sources"] = sorted({s["source_id"] for s in adjusted_steps if isinstance(s.get("source_id"), str)})
    adjusted["campaign_csv"] = None  # keep base csv; adjusted steps are authoritative

    return {
        "ok": len(errors) == 0,
        "base": base,
        "adjusted": adjusted,
        "errors": errors,
        "corrections": corrections,
    }

