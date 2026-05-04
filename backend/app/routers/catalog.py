from fastapi import APIRouter

from app.campaigns.apt_mitre import apt_mitre_steps
from app.sources.registry import all_sources

router = APIRouter(prefix="/api", tags=["catalog"])


@router.get("/sources")
def list_sources():
    out = []
    for s in all_sources():
        out.append(
            {
                "id": s.id,
                "label": s.label,
                "framing": s.framing,
                "pri_default": s.pri_default,
                "os_family": s.os_family,
                "event_types": [{"id": e.id, "label": e.label, "schema": e.schema} for e in s.list_event_types()],
            }
        )
    return out


@router.get("/campaigns")
def list_campaigns():
    steps = apt_mitre_steps()
    return [
        {
            "id": "apt_mitre",
            "label": "APT MITRE (condensed)",
            "steps": [
                {
                    "idx": st.idx,
                    "tactic": st.tactic,
                    "technique": st.technique,
                    "source_id": st.source_id,
                    "event_type": st.event_type,
                    "params": st.params,
                    "delay_after": st.delay_after,
                }
                for st in steps
            ],
        }
    ]
