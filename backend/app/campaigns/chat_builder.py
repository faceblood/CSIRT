from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CampaignStep:
    tactic: str
    technique: str
    source_id: str
    event_type: str
    count: int
    delay_s: int
    params_json: str = "{}"


def _noise_level(rate: int) -> str:
    if rate <= 3:
        return "Low"
    if rate <= 7:
        return "Medium"
    return "High"


def _detect_profile(prompt: str) -> str:
    p = prompt.lower()
    if "stealth" in p or "sigilosa" in p:
        return "stealth"
    if "brute" in p or "fuerza bruta" in p:
        return "bruteforce"
    if "ransom" in p or "lockbit" in p:
        return "ransomware"
    if "soc" in p and "ruido" in p:
        return "soc_noise"
    return "apt"


def _base_steps(profile: str) -> list[CampaignStep]:
    if profile == "ransomware":
        return [
            CampaignStep("Initial Access", "T1566", "fortimail", "phishing_detected", 8, 3),
            CampaignStep("Execution", "T1059.001", "windows", "4688", 16, 2, '{"process":"powershell.exe"}'),
            CampaignStep("Detection", "T1486", "fortiedr", "ransomware", 18, 2),
            CampaignStep("Command and Control", "T1071.004", "fortigate", "dns_query", 30, 1, '{"qname":"update-cdn.example"}'),
            CampaignStep("Impact", "T1490", "vmware", "snapshot_delete", 10, 2),
            CampaignStep("Impact", "T1529", "vmware", "vm_power_off", 8, 2),
        ]
    if profile == "bruteforce":
        return [
            CampaignStep("Credential Access", "T1110.001", "linux", "sshd_failed", 30, 2),
            CampaignStep("Credential Access", "T1110.001", "windows", "4625", 25, 2),
            CampaignStep("Credential Access", "T1110", "vmware", "vcenter_failed_login", 15, 2),
            CampaignStep("Defense", "N/A", "fortigate", "traffic_deny", 20, 2),
        ]
    if profile == "soc_noise":
        return [
            CampaignStep("Initial Access", "T1566", "fortimail", "phishing_detected", 14, 1),
            CampaignStep("Execution", "T1059.001", "windows", "4688", 30, 1, '{"process":"powershell.exe"}'),
            CampaignStep("Detection", "T1486", "fortiedr", "ransomware", 24, 1),
            CampaignStep("Command and Control", "T1071.004", "fortigate", "dns_query", 60, 1, '{"qname":"soc-noise.example"}'),
            CampaignStep("Defense", "N/A", "fortigate", "traffic_deny", 40, 1),
        ]
    if profile == "stealth":
        return [
            CampaignStep("Initial Access", "T1566", "fortimail", "phishing_detected", 2, 20),
            CampaignStep("Execution", "T1059.001", "windows", "4688", 4, 15, '{"process":"powershell.exe"}'),
            CampaignStep("Discovery", "T1082", "linux", "audit_execve", 5, 20),
            CampaignStep("Command and Control", "T1071.004", "fortigate", "dns_query", 8, 12, '{"qname":"cdn-check.example"}'),
        ]
    # apt default
    return [
        CampaignStep("Initial Access", "T1566", "fortimail", "phishing_detected", 6, 4),
        CampaignStep("Execution", "T1059.001", "windows", "4688", 10, 3, '{"process":"powershell.exe"}'),
        CampaignStep("Credential Access", "T1110.001", "windows", "4625", 12, 3),
        CampaignStep("Discovery", "T1082", "linux", "audit_execve", 10, 4),
        CampaignStep("Lateral Movement", "T1021", "fortiedr", "lateral_movement", 8, 4),
        CampaignStep("Command and Control", "T1071.004", "fortigate", "dns_query", 16, 3, '{"qname":"stage-check.example"}'),
    ]


def _apply_modifiers(prompt: str, steps: list[CampaignStep]) -> tuple[int, int]:
    p = prompt.lower()
    rate = 5
    base_count = sum(s.count for s in steps)

    if "agresiva" in p or "aggressive" in p:
        rate = 10
        for s in steps:
            s.count = int(s.count * 1.6)
            s.delay_s = max(1, int(s.delay_s * 0.6))
    if "stealth" in p:
        rate = min(rate, 2)
        for s in steps:
            s.count = max(1, int(s.count * 0.5))
            s.delay_s = max(4, int(s.delay_s * 1.8))
    if "más dns" in p or "mas dns" in p:
        for s in steps:
            if s.source_id == "fortigate" and s.event_type == "dns_query":
                s.count = int(s.count * 2.2)
    if "más fortiedr" in p or "mas fortiedr" in p:
        for s in steps:
            if s.source_id == "fortiedr":
                s.count = int(s.count * 2)
        if not any(s.source_id == "fortiedr" for s in steps):
            steps.append(CampaignStep("Detection", "T1059.001", "fortiedr", "suspicious_process", 16, 2))
    if "más vmware" in p or "mas vmware" in p:
        vm_steps = [s for s in steps if s.source_id == "vmware"]
        if vm_steps:
            for s in vm_steps:
                s.count = int(s.count * 1.8)
        else:
            steps.extend(
                [
                    CampaignStep("Discovery", "T1595", "vmware", "vcenter_inventory_enum", 10, 2),
                    CampaignStep("Impact", "T1490", "vmware", "snapshot_delete", 8, 2),
                ]
            )

    total_count = sum(s.count for s in steps)
    if total_count <= 150 and rate > 3:
        rate = 5
    if total_count > 350:
        rate = max(rate, 10)
    if total_count > 500:
        rate = max(rate, 12)
    return rate, total_count if total_count > 0 else base_count


def _steps_to_csv(steps: list[CampaignStep]) -> str:
    lines = ["step,tactic,technique,source_id,event_type,count,delay_s,params_json"]
    for idx, st in enumerate(steps, start=1):
        lines.append(
            f'{idx},{st.tactic},{st.technique},{st.source_id},{st.event_type},{st.count},{st.delay_s},"{st.params_json.replace(chr(34), chr(34) * 2)}"'
        )
    return "\n".join(lines)


def build_campaign_from_prompt(prompt: str) -> dict:
    profile = _detect_profile(prompt)
    steps = _base_steps(profile)
    rate, count = _apply_modifiers(prompt, steps)
    noise = _noise_level(rate)
    sources = sorted({s.source_id for s in steps})
    campaign_id = f"{profile}-chat-generated"
    cli = (
        "python fortisiem_log_sender.py "
        f"--campaign {campaign_id} "
        f"--sources {','.join(sources)} "
        f"--count {count} "
        f"--rate {rate} "
        "--src-ip-mode random"
    )
    flow = [f"{i}. {s.tactic}: {s.source_id}/{s.event_type}" for i, s in enumerate(steps, start=1)]
    return {
        "campaign_summary": {"id": campaign_id, "profile": profile, "prompt": prompt},
        "flow_ttp": flow,
        "sources": sources,
        "cli": cli,
        "campaign_csv": _steps_to_csv(steps),
        "recommendations": {"rate": rate, "count": count, "delay_hint": "Increase delays for stealth; reduce for aggressive/noise."},
        "soc_noise_level": noise,
        "steps": [s.__dict__ for s in steps],
    }
