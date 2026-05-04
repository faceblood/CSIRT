from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.exercise_store import exercise_store, parse_offset
from app.core import jobs as jobs_core

router = APIRouter(prefix="/api/exercises", tags=["exercises"])


class ExerciseRunBody(BaseModel):
    actors: dict[str, str | None] = Field(default_factory=dict)
    time_scale: float = 1.0
    fortisiem_ip: str | None = None
    fortisiem_port: int | None = None


@router.post("/jobs/{jid}/stop")
async def stop_job(jid: str):
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    ok = await jobs_core.job_manager.stop(jid)
    if not ok:
        raise HTTPException(404)
    return {"ok": True}


@router.get("/jobs/{jid}")
def job_status(jid: str):
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    rec = jobs_core.job_manager.jobs.get(jid)
    if not rec:
        raise HTTPException(404)
    return {"id": rec.id, "kind": rec.kind, "status": rec.status, "meta": rec.meta}


@router.get("")
def list_exercises():
    exercise_store.ensure_dir()
    exercise_store.seed_defaults()
    rows = []
    for eid in exercise_store.list_ids():
        doc = exercise_store.load(eid)
        rows.append(
            {
                "id": doc.get("id", eid),
                "label": doc.get("label", eid),
                "description": doc.get("description", ""),
                "inject_count": len(doc.get("injects", [])),
                "required_actors": doc.get("required_actors", []),
            }
        )
    return rows


@router.get("/{eid}/timeline")
def exercise_timeline(eid: str):
    """Sorted inject indices matching the exercise runner (for jump-to targeting)."""
    exercise_store.seed_defaults()
    try:
        doc = exercise_store.load(eid)
    except FileNotFoundError:
        raise HTTPException(404)
    injects = sorted(
        doc.get("injects", []),
        key=lambda inj: parse_offset(str(inj.get("offset", "0"))).total_seconds(),
    )
    return {
        "id": doc.get("id", eid),
        "label": doc.get("label", eid),
        "injects": [
            {"idx": i + 1, "name": inj.get("name", ""), "offset": str(inj.get("offset", ""))}
            for i, inj in enumerate(injects)
        ],
    }


@router.get("/{eid}")
def get_exercise(eid: str):
    exercise_store.seed_defaults()
    try:
        return exercise_store.load(eid)
    except FileNotFoundError:
        raise HTTPException(404)


@router.post("")
def save_exercise(doc: dict):
    exercise_store.ensure_dir()
    eid = doc.get("id")
    if not eid:
        raise HTTPException(400, detail="missing id")
    exercise_store.save(str(eid), doc)
    return {"ok": True}


@router.delete("/{eid}")
def delete_exercise(eid: str):
    if not exercise_store.delete(eid):
        raise HTTPException(404)
    return {"ok": True}


@router.post("/{eid}/run")
def run_exercise(eid: str, body: ExerciseRunBody):
    exercise_store.seed_defaults()
    try:
        exercise_store.load(eid)
    except FileNotFoundError:
        raise HTTPException(404)
    if jobs_core.job_manager is None:
        raise HTTPException(503)
    jid = jobs_core.job_manager.spawn_exercise(
        exercise_id=eid,
        actors=body.actors,
        time_scale=body.time_scale,
        fortisiem_ip=body.fortisiem_ip,
        fortisiem_port=body.fortisiem_port,
    )
    return {"job_id": jid}
