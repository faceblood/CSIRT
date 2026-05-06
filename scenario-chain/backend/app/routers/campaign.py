from __future__ import annotations

import csv
import io
import json
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.sources.registry import all_sources

router = APIRouter(tags=["campaign"])


class CampaignCsvParseBody(BaseModel):
    csv_text: str = Field(min_length=1, description="CSV text including header row.")


def _catalog() -> dict[str, set[str]]:
    return {s.id: {et.id for et in s.list_event_types()} for s in all_sources()}


@router.post("/campaign/parse")
def parse_campaign_csv(body: CampaignCsvParseBody):
    """
    Parses a campaign CSV into Scenario-Chain steps.

    Expected columns:
    - step_id (optional)
    - source_id (required)
    - event_type (required)
    - count (required)
    - params_json (optional; JSON object as string)
    """
    cat = _catalog()

    reader = csv.DictReader(io.StringIO(body.csv_text))
    rows = list(reader)

    steps: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for i, r in enumerate(rows, start=1):
        source_id = (r.get("source_id") or "").strip()
        event_type = (r.get("event_type") or "").strip()
        step_id = (r.get("step_id") or str(i)).strip()

        raw_count = (r.get("count") or "").strip()
        try:
            count = int(raw_count)
        except Exception:
            count = -1

        params_raw = (r.get("params_json") or "").strip()
        if not params_raw:
            params_raw = "{}"

        try:
            params = json.loads(params_raw)
            if not isinstance(params, dict):
                raise ValueError("params_json must be a JSON object")
        except Exception as e:
            errors.append({"row": i, "step_id": step_id, "type": "invalid_params_json", "detail": str(e)})
            continue

        if not source_id:
            errors.append({"row": i, "step_id": step_id, "type": "missing_source_id"})
            continue
        if source_id not in cat:
            errors.append(
                {
                    "row": i,
                    "step_id": step_id,
                    "type": "unknown_source_id",
                    "source_id": source_id,
                    "available_sources": sorted(cat.keys()),
                }
            )
            continue

        if not event_type:
            errors.append({"row": i, "step_id": step_id, "type": "missing_event_type"})
            continue
        if event_type not in cat[source_id]:
            errors.append(
                {
                    "row": i,
                    "step_id": step_id,
                    "type": "unknown_event_type",
                    "source_id": source_id,
                    "event_type": event_type,
                    "available_event_types": sorted(cat[source_id]),
                }
            )
            continue

        if count < 1:
            errors.append({"row": i, "step_id": step_id, "type": "invalid_count", "count": raw_count})
            continue

        steps.append(
            {
                "step_id": step_id,
                "source_id": source_id,
                "event_type": event_type,
                "count": count,
                "params": params,
            }
        )

    return {"ok": len(errors) == 0, "steps": steps, "errors": errors, "row_count": len(rows)}

