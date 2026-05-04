from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from dataclasses import dataclass, field
import random
import threading
from typing import Any
from uuid import uuid4

from app.campaigns.apt_mitre import apt_mitre_steps
from app.config import settings
from app.core.history import HistoryBuffer
from app.core.inventory_store import InventoryStore, inventory_store
from app.core.exercise_store import exercise_store, parse_offset
from app.core.syslog import send_payload
from app.sources.registry import get_source


def _resolve_actor_hosts(store: InventoryStore, actors: dict[str, str | None]) -> dict[str, str]:
    """Map actor slot -> host_id for *_ref keys."""
    out: dict[str, str] = {}
    mapping = {
        "victim_linux": actors.get("victim_linux_id"),
        "victim_windows": actors.get("victim_windows_id"),
        "fortigate": actors.get("fortigate_id"),
        "fortiproxy": actors.get("fortiproxy_id"),
        "domain_controller": actors.get("domain_controller_id"),
        "fortiweb": actors.get("fortiweb_id"),
        "fortimail": actors.get("fortimail_id"),
        "dlp_endpoint": actors.get("dlp_endpoint_id"),
        "ot_host": actors.get("ot_host_id"),
    }
    for k, v in mapping.items():
        if v:
            out[k] = v
    return out


def _resolve_step_params(raw: dict[str, Any], actor_hosts: dict[str, str], actors: dict[str, str | None]) -> dict[str, Any]:
    params = dict(raw)
    href = params.pop("host_id_ref", None)
    if href:
        hid = actor_hosts.get(href)
        if hid:
            params["host_id"] = hid
    uref = params.pop("user_id_ref", None)
    if uref == "user" and actors.get("user_id"):
        params["user_id"] = actors["user_id"]
    return params


@dataclass
class JobRecord:
    id: str
    kind: str
    status: str = "running"
    meta: dict[str, Any] = field(default_factory=dict)
    task: asyncio.Task | None = None
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    pause: asyncio.Event = field(default_factory=asyncio.Event)  # set() => paused


async def pause_gate(rec: JobRecord) -> None:
    """Block while job is paused (pause Event is set)."""
    while rec.pause.is_set():
        if rec.cancel.is_set():
            return
        await asyncio.sleep(0.15)


def _collector_endpoint(rec: JobRecord) -> tuple[str, int]:
    """UDP syslog destination for this job (optional overrides in rec.meta)."""
    ip = rec.meta.get("fortisiem_ip") or settings.fortisiem_ip
    raw_port = rec.meta.get("fortisiem_port")
    port = int(raw_port) if raw_port is not None else settings.fortisiem_port
    return ip, port


def _clamp_inject_1based(raw: Any, n_injects: int) -> int:
    """Return 1-based inject index clamped to [1, max(1, n_injects)]."""
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return 1
    hi = max(1, n_injects)
    return max(1, min(v, hi))


_app_loop: asyncio.AbstractEventLoop | None = None


def _spawn_background(coro: Coroutine[Any, Any, None]) -> asyncio.Task:
    """Schedule a background job coroutine on the ASGI event loop.

    Works when the HTTP handler runs on the loop (``async def``) or in Starlette's
    thread pool (sync ``def``): the latter has no running loop in that thread.
    """
    try:
        return asyncio.get_running_loop().create_task(coro)
    except RuntimeError:
        pass
    loop = _app_loop
    if loop is None:
        raise RuntimeError(
            "Job manager is not bound to the asyncio loop (app lifespan did not run init_job_manager(loop))."
        )

    box: dict[str, asyncio.Task | None] = {}
    done = threading.Event()

    def _post() -> None:
        box["task"] = loop.create_task(coro)
        done.set()

    loop.call_soon_threadsafe(_post)
    if not done.wait(timeout=15.0):
        raise RuntimeError("Timeout scheduling background job on the event loop")
    t = box.get("task")
    if t is None:
        raise RuntimeError("Background task was not created")
    return t


def _take_jump_idx(rec: JobRecord, n_injects: int) -> int | None:
    """Pop jump_to_inject from meta and return 0-based index, or None."""
    if "jump_to_inject" not in rec.meta:
        return None
    raw = rec.meta.pop("jump_to_inject", None)
    return _clamp_inject_1based(raw, n_injects) - 1


class JobManager:
    def __init__(self, history: HistoryBuffer):
        self.history = history
        self.jobs: dict[str, JobRecord] = {}

    def spawn_playbook(
        self,
        *,
        actors: dict[str, str | None],
        mode: str,
        step_delay: float,
        fortisiem_ip: str | None = None,
        fortisiem_port: int | None = None,
        inventory: InventoryStore | None = None,
    ):
        store = inventory or inventory_store
        jid = str(uuid4())
        meta: dict[str, Any] = {"mode": mode, "actors": actors}
        if fortisiem_ip:
            meta["fortisiem_ip"] = fortisiem_ip
        if fortisiem_port is not None:
            meta["fortisiem_port"] = fortisiem_port
        rec = JobRecord(id=jid, kind="playbook", meta=meta)
        actor_hosts = _resolve_actor_hosts(store, actors)

        async def runner():
            steps = apt_mitre_steps()
            for i, st in enumerate(steps):
                await pause_gate(rec)
                if rec.cancel.is_set():
                    rec.status = "cancelled"
                    return
                params = _resolve_step_params(st.params, actor_hosts, actors)
                src = get_source(st.source_id)
                built = src.build_event(event_type=st.event_type, params=params, inventory=store)
                dst_ip, dst_port = _collector_endpoint(rec)
                status, _ok = send_payload(
                    reporting_ip=built.reporting_ip,
                    payload=built.payload,
                    fortisiem_ip=dst_ip,
                    fortisiem_port=dst_port,
                    dry_run=False,
                )
                self.history.add(
                    reporting_ip=built.reporting_ip,
                    hostname=built.hostname,
                    status=status,
                    dry_run=False,
                    payload=built.payload,
                    source_id=st.source_id,
                    job_id=jid,
                    meta={"campaign": "apt_mitre", "step": st.idx, "tactic": st.tactic},
                )
                rec.meta["current_step"] = i + 1
                await asyncio.sleep(max(st.delay_after, step_delay))
                if mode == "manual":
                    # wait for external step trigger — simplified: treat manual same as auto with longer pause not implemented
                    pass
            rec.status = "completed"

        rec.task = _spawn_background(runner())
        self.jobs[jid] = rec
        return jid

    def spawn_keepalive(
        self,
        *,
        interval_seconds: float,
        fortisiem_ip: str | None = None,
        fortisiem_port: int | None = None,
        inventory: InventoryStore | None = None,
    ):
        store = inventory or inventory_store
        jid = str(uuid4())
        meta: dict[str, Any] = {}
        if fortisiem_ip:
            meta["fortisiem_ip"] = fortisiem_ip
        if fortisiem_port is not None:
            meta["fortisiem_port"] = fortisiem_port
        rec = JobRecord(id=jid, kind="keepalive", meta=meta)

        async def runner():
            while not rec.cancel.is_set():
                await pause_gate(rec)
                if rec.cancel.is_set():
                    break
                for h in store.list_hosts():
                    if h.os_family == "linux":
                        src = get_source("linux")
                        et = "baseline_cron"
                    elif h.os_family == "fortigate":
                        src = get_source("fortigate")
                        et = "baseline_traffic"
                    elif h.os_family == "fortiproxy":
                        src = get_source("fortiproxy")
                        et = "baseline_webfilter"
                    else:
                        continue
                    await pause_gate(rec)
                    if rec.cancel.is_set():
                        break
                    built = src.build_event(event_type=et, params={"host_id": h.id}, inventory=store)
                    dst_ip, dst_port = _collector_endpoint(rec)
                    send_payload(
                        reporting_ip=built.reporting_ip,
                        payload=built.payload,
                        fortisiem_ip=dst_ip,
                        fortisiem_port=dst_port,
                        dry_run=False,
                    )
                    self.history.add(
                        reporting_ip=built.reporting_ip,
                        hostname=built.hostname,
                        status="sent",
                        dry_run=False,
                        payload=built.payload,
                        source_id=src.id,
                        job_id=jid,
                        meta={"keepalive": True},
                    )
                    await asyncio.sleep(0.2)
                if rec.cancel.is_set():
                    break
                await asyncio.sleep(max(1.0, interval_seconds))

        rec.task = _spawn_background(runner())
        self.jobs[jid] = rec
        return jid

    def spawn_exercise(
        self,
        *,
        exercise_id: str,
        actors: dict[str, str | None],
        time_scale: float,
        fortisiem_ip: str | None = None,
        fortisiem_port: int | None = None,
        inventory: InventoryStore | None = None,
    ):
        store = inventory or inventory_store
        exercise_store.seed_defaults()
        doc = exercise_store.load(exercise_id)
        jid = str(uuid4())
        meta: dict[str, Any] = {"exercise_id": exercise_id, "time_scale": time_scale}
        if fortisiem_ip:
            meta["fortisiem_ip"] = fortisiem_ip
        if fortisiem_port is not None:
            meta["fortisiem_port"] = fortisiem_port
        rec = JobRecord(id=jid, kind="exercise", meta=meta)
        actor_hosts = _resolve_actor_hosts(store, actors)

        async def runner():
            loop_start = asyncio.get_running_loop().time()
            injects = sorted(doc.get("injects", []), key=lambda inj: parse_offset(inj["offset"]).total_seconds())
            n_injects = len(injects)
            rec.meta["total_injects"] = n_injects
            idx = 0
            while idx < n_injects:
                await pause_gate(rec)
                if rec.cancel.is_set():
                    rec.status = "cancelled"
                    return

                j0 = _take_jump_idx(rec, n_injects)
                if j0 is not None:
                    idx = j0

                inj = injects[idx]
                rec.meta["current_inject_idx"] = idx + 1
                rec.meta["current_inject"] = inj.get("name")

                skip_rest = False
                jump_to: int | None = None
                target_sec = parse_offset(str(inj["offset"])).total_seconds() / max(float(time_scale), 0.001)
                while not rec.cancel.is_set():
                    await pause_gate(rec)
                    jt = _take_jump_idx(rec, n_injects)
                    if jt is not None and jt != idx:
                        jump_to = jt
                        skip_rest = True
                        break
                    if rec.meta.pop("skip_current_inject", False):
                        skip_rest = True
                        break
                    elapsed = asyncio.get_running_loop().time() - loop_start
                    remain = target_sec - elapsed
                    if remain <= 0:
                        break
                    await asyncio.sleep(min(remain, 0.25))

                if rec.cancel.is_set():
                    rec.status = "cancelled"
                    return

                if skip_rest:
                    if jump_to is not None:
                        idx = jump_to
                    else:
                        rec.meta["completed_injects"] = idx + 1
                        idx += 1
                    continue

                skip_rest = False
                jump_to = None
                for action in inj.get("log_actions", []):
                    await pause_gate(rec)
                    if rec.cancel.is_set():
                        rec.status = "cancelled"
                        return
                    jt = _take_jump_idx(rec, n_injects)
                    if jt is not None and jt != idx:
                        jump_to = jt
                        skip_rest = True
                        break
                    if rec.meta.pop("skip_current_inject", False):
                        skip_rest = True
                        break
                    params = dict(action.get("params") or {})
                    params = _resolve_step_params(params, actor_hosts, actors)
                    repeats = int(action.get("count", 1) or 1)
                    for _ in range(max(1, repeats)):
                        src = get_source(action["source_id"])
                        built = src.build_event(event_type=action["event_type"], params=params, inventory=store)
                        dst_ip, dst_port = _collector_endpoint(rec)
                        status, _ok = send_payload(
                            reporting_ip=built.reporting_ip,
                            payload=built.payload,
                            fortisiem_ip=dst_ip,
                            fortisiem_port=dst_port,
                            dry_run=False,
                        )
                        self.history.add(
                            reporting_ip=built.reporting_ip,
                            hostname=built.hostname,
                            status=status,
                            dry_run=False,
                            payload=built.payload,
                            source_id=action["source_id"],
                            job_id=jid,
                            meta={"exercise": exercise_id, "inject": inj.get("name")},
                        )

                if skip_rest:
                    if jump_to is not None:
                        idx = jump_to
                    else:
                        rec.meta["completed_injects"] = idx + 1
                        idx += 1
                    continue

                rec.meta["completed_injects"] = idx + 1
                idx += 1

            rec.status = "completed"

        rec.task = _spawn_background(runner())
        self.jobs[jid] = rec
        return jid

    def spawn_simulate(
        self,
        *,
        plan: list[dict[str, Any]],
        min_delay: float,
        max_delay: float,
        loop: bool,
        interval_seconds: float,
        max_rounds: int,
        fortisiem_ip: str | None = None,
        fortisiem_port: int | None = None,
        inventory: InventoryStore | None = None,
    ):
        store = inventory or inventory_store
        jid = str(uuid4())
        meta: dict[str, Any] = {"plan": plan, "round": 0}
        if fortisiem_ip:
            meta["fortisiem_ip"] = fortisiem_ip
        if fortisiem_port is not None:
            meta["fortisiem_port"] = fortisiem_port
        rec = JobRecord(id=jid, kind="simulate", meta=meta)

        async def runner():
            rounds = 0
            while True:
                if rec.cancel.is_set():
                    rec.status = "cancelled"
                    return
                await pause_gate(rec)
                rec.meta["round"] = rounds + 1
                for item in plan:
                    await pause_gate(rec)
                    if rec.cancel.is_set():
                        rec.status = "cancelled"
                        return
                    src_id = item["source_id"]
                    event_types = list(item.get("event_types") or [])
                    count = max(1, int(item.get("count", 1)))
                    params = dict(item.get("params") or {})
                    hid = item.get("host_id")
                    if hid:
                        params.setdefault("host_id", hid)
                    src = get_source(src_id)
                    for _ in range(count):
                        await pause_gate(rec)
                        if rec.cancel.is_set():
                            rec.status = "cancelled"
                            return
                        types_pool = event_types if event_types else [e.id for e in src.list_event_types()]
                        et = random.choice(types_pool)
                        built = src.build_event(event_type=et, params=params, inventory=store)
                        dst_ip, dst_port = _collector_endpoint(rec)
                        status, _ok = send_payload(
                            reporting_ip=built.reporting_ip,
                            payload=built.payload,
                            fortisiem_ip=dst_ip,
                            fortisiem_port=dst_port,
                            dry_run=False,
                        )
                        self.history.add(
                            reporting_ip=built.reporting_ip,
                            hostname=built.hostname,
                            status=status,
                            dry_run=False,
                            payload=built.payload,
                            source_id=src_id,
                            job_id=jid,
                            meta={"simulate": True, "event_type": et},
                        )
                        await asyncio.sleep(random.uniform(min_delay, max_delay))
                rounds += 1
                if not loop:
                    break
                if max_rounds and rounds >= max_rounds:
                    break
                await asyncio.sleep(max(1.0, interval_seconds))
            rec.status = "completed"

        rec.task = _spawn_background(runner())
        self.jobs[jid] = rec
        return jid

    def pause(self, jid: str) -> bool:
        rec = self.jobs.get(jid)
        if not rec:
            return False
        rec.pause.set()
        rec.meta["paused"] = True
        return True

    def resume(self, jid: str) -> bool:
        rec = self.jobs.get(jid)
        if not rec:
            return False
        rec.pause.clear()
        rec.meta["paused"] = False
        return True

    def skip_exercise_inject(self, jid: str) -> bool:
        rec = self.jobs.get(jid)
        if not rec or rec.kind != "exercise":
            return False
        rec.meta["skip_current_inject"] = True
        return True

    def jump_exercise_to(self, jid: str, inject_idx_1based: int) -> bool:
        rec = self.jobs.get(jid)
        if not rec or rec.kind != "exercise":
            return False
        rec.meta["jump_to_inject"] = inject_idx_1based
        return True

    async def stop(self, jid: str) -> bool:
        rec = self.jobs.get(jid)
        if not rec:
            return False
        rec.cancel.set()
        if rec.task:
            rec.task.cancel()
            try:
                await rec.task
            except asyncio.CancelledError:
                pass
        rec.status = "stopped"
        return True


job_manager: JobManager | None = None


def init_job_manager(history: HistoryBuffer, app_loop: asyncio.AbstractEventLoop | None = None) -> JobManager:
    global job_manager, _app_loop
    _app_loop = app_loop
    job_manager = JobManager(history)
    return job_manager
