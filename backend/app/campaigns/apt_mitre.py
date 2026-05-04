from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class CampaignStep:
    idx: int
    tactic: str
    technique: str
    source_id: str
    event_type: str
    params: dict[str, Any]
    delay_after: float = 0.5


def apt_mitre_steps() -> list[CampaignStep]:
    """Condensed APT-style chain (subset of sabadotarde2 scenario). Params use placeholders resolved at runtime."""
    return [
        CampaignStep(1, "Reconnaissance", "T1595", "fortigate", "traffic_deny", {"host_id_ref": "fortigate"}),
        CampaignStep(2, "Initial Access", "T1110", "linux", "sshd_failed", {"host_id_ref": "victim_linux"}),
        CampaignStep(3, "Initial Access", "T1078", "linux", "sshd_accepted", {"host_id_ref": "victim_linux", "user_id_ref": "user"}),
        CampaignStep(4, "Privilege Escalation", "T1548", "linux", "sudo", {"host_id_ref": "victim_linux", "user_id_ref": "user"}),
        CampaignStep(5, "Execution", "T1059", "windows", "4688", {"host_id_ref": "victim_windows", "user_id_ref": "user"}),
        CampaignStep(6, "Command and Control", "T1071.001", "fortiproxy", "webfilter_passthrough", {"host_id_ref": "fortiproxy", "user_id_ref": "user"}),
        CampaignStep(7, "Command and Control", "T1071", "fortigate", "dns_query", {"host_id_ref": "fortigate"}),
        CampaignStep(8, "Impact", "T1486", "fortiedr", "ransomware", {"host_id_ref": "victim_windows", "include_ransomware": True}),
    ]
