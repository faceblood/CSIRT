from __future__ import annotations

import csv
import json
import importlib.util
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from app.config import settings
from app.core.inventory_store import InventoryStore, inventory_store
from app.sources.base import BuiltEvent, EventTypeSpec, Framing


def _fedr_stub():
    """Minimal stand-in when the external script is missing or cannot register signals (non-main thread).

    Implements the same surface as ``fortiedr_extended_ttp_scapy_v3.py`` so ``build_event`` works and
    emits a short RFC5424-style stub line (replace the script in repo root for full TTP bodies).
    """

    def load_data(args: Any) -> dict[str, Any]:
        return {
            "endpoints": [
                {
                    "hostname": "WIN-LAB-01",
                    "ip": "10.0.10.30",
                    "os": "Windows 11 Pro",
                    "os_family": "windows",
                    "group": "Endpoints",
                }
            ]
        }

    def pick_ep(data: dict[str, Any], os_filter: str) -> dict[str, Any]:
        eps = data.get("endpoints") or []
        if not eps:
            return {"hostname": "UNKNOWN", "ip": "127.0.0.1"}
        return eps[0]

    def pick_reporting(args: Any, data: dict[str, Any]) -> dict[str, str]:
        rip = getattr(args, "reporting_ip", None) or "172.16.20.110"
        return {"ip": str(rip), "name": getattr(args, "reporting_name", None) or "FORTIEDR-CM-01"}

    def syslog_msg(args: Any, reporting: dict[str, str], body: Any) -> str:
        line = json.dumps(
            {
                "stub": True,
                "body": body,
                "collector": reporting.get("ip"),
            },
            ensure_ascii=False,
        )
        pri = getattr(args, "pri", "<134>") or "<134>"
        return f"{pri}1 {line}\n"

    def _gen_stub(_args: Any, _data: dict[str, Any], ep: dict[str, Any]) -> dict[str, Any]:
        return {
            "message": "FortiEDR stub event (install fortiedr_extended_ttp_scapy_v3.py in repo root for full TTPs)",
            "endpoint": ep.get("hostname", "?"),
        }

    return SimpleNamespace(
        load_data=load_data,
        pick_ep=pick_ep,
        pick_reporting=pick_reporting,
        syslog_msg=syslog_msg,
        GEN={"ransomware": _gen_stub, "stub_edr": _gen_stub},
    )


def _load_fedr_module():
    path = settings.repo_root / "fortiedr_extended_ttp_scapy_v3.py"
    if not path.is_file():
        return _fedr_stub()
    spec = importlib.util.spec_from_file_location("fedr_ext", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except ValueError as e:
        # External script registers SIGINT at import; threadpool workers are not the main thread.
        if "main thread" in str(e).lower() or "signal" in str(e).lower():
            return _fedr_stub()
        raise
    return mod


def _write_csv_rows(preferred: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> Path:
    """Write CSV; on permission errors under data_dir, fall back to the system temp directory."""
    candidates = [preferred, Path(tempfile.gettempdir()) / f"csirt_{os.getpid()}_{preferred.name}"]
    err: OSError | None = None
    for out in candidates:
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames)
                w.writeheader()
                for r in rows:
                    w.writerow(r)
            return out.resolve()
        except OSError as e:
            err = e
            continue
    raise PermissionError(f"Cannot write {preferred} (tried temp fallback): {err}") from err


def _write_endpoints_csv(store: InventoryStore, preferred: Path) -> Path:
    rows: list[dict[str, Any]] = []
    for h in store.list_hosts():
        if h.os_family not in ("windows", "linux"):
            continue
        fam = "windows" if h.os_family == "windows" else "linux"
        rows.append(
            {
                "hostname": h.hostname,
                "ip": h.ip,
                "os": h.os or ("Windows 11" if fam == "windows" else "Linux"),
                "os_family": fam,
                "group": h.group or "Endpoints",
            }
        )
    if not rows:
        rows.append(
            {
                "hostname": "WIN-LAB-01",
                "ip": "10.0.10.30",
                "os": "Windows 11 Pro 23H2",
                "os_family": "windows",
                "group": "Lab",
            }
        )
    return _write_csv_rows(preferred, ["hostname", "ip", "os", "os_family", "group"], rows)


class FortiEdrSource:
    id = "fortiedr"
    label = "FortiEDR"
    framing: Framing = "rfc5424"
    pri_default = "<134>"
    os_family = None

    def __init__(self):
        self._mod = None

    @property
    def mod(self):
        if self._mod is None:
            self._mod = _load_fedr_module()
        return self._mod

    def list_event_types(self) -> list[EventTypeSpec]:
        m = self.mod
        ttps = [k for k in getattr(m, "GEN", {}).keys() if k != "all"]
        return [EventTypeSpec(t, t.replace("_", " ").title(), {"ttp": "string", "host_id": "string?"}) for t in ttps]

    def _build_args(
        self,
        store: InventoryStore,
        *,
        fortisiem_ip: str | None,
        fortisiem_port: int | None,
        params: dict[str, Any],
    ):
        ddir = store.data_dir
        endpoints_path = _write_endpoints_csv(store, ddir / "_generated_endpoints.csv")
        inst = settings.repo_root / "escenarios" / "instrumentacion"
        proc = inst / "processes.csv"
        proc_path = str(proc) if proc.exists() else "/nonexistent/processes.csv"
        rep_pool = self._ensure_reporting_csv(store, ddir / "_generated_reporting.csv")
        return SimpleNamespace(
            fortisiem_ip=fortisiem_ip or settings.fortisiem_ip,
            port=fortisiem_port or settings.fortisiem_port,
            pri=params.get("pri", "<134>"),
            tz_offset=int(params.get("tz_offset", 2)),
            reporting_mode=params.get("reporting_mode", "random"),
            reporting_ip=params.get("reporting_ip", "172.16.20.110"),
            reporting_name=params.get("reporting_name"),
            reporting_pool_file=str(rep_pool),
            users_file=str(store.users_path),
            malware_file="/nonexistent/malware.csv",
            c2_file=str(store.c2_path),
            attackers_file=str(store.c2_path),
            c2_domains_file="/nonexistent/c2d.txt",
            c2_routes_file="/nonexistent/routes.txt",
            external_nodes_file="/nonexistent/ext.csv",
            endpoints_file=str(endpoints_path),
            processes_file=proc_path,
            commands_file="/nonexistent/commands.txt",
            tenant_id=params.get("tenant_id", "LAB-TENANT-ID"),
            tenant_name=params.get("tenant_name", "LAB-TENANT"),
            exercise_id=params.get("exercise_id", "FORTIEDR-EXTENDED"),
            ttps=[params.get("ttp", "suspicious_process")],
            actions=list(params.get("actions", ["Log", "Block"])),
            os_filter=params.get("os_filter", "any"),
            include_ransomware=bool(params.get("include_ransomware", False)),
            ransomware_intensity=params.get("ransomware_intensity", "medium"),
            use_external_nodes=bool(params.get("use_external_nodes", False)),
            external_node_ratio=float(params.get("external_node_ratio", 0.35)),
            attacker_remote_ratio=float(params.get("attacker_remote_ratio", 0.25)),
            dry_run=True,
        )

    def _ensure_reporting_csv(self, store: InventoryStore, preferred: Path) -> Path:
        # Use FortiEDR-like collector hosts if present, else first non-appliance IP
        collectors = [h for h in store.list_hosts() if "fortiedr" in (h.group or "").lower() or "edr" in (h.role or "").lower()]
        rows: list[dict[str, Any]] = []
        for h in collectors or store.list_hosts()[:3]:
            rows.append({"ip": h.resolved_reporting_ip(), "name": h.hostname})
        if not rows:
            rows.append({"ip": "172.16.20.110", "name": "FORTIEDR-CM-01"})
        return _write_csv_rows(preferred, ["ip", "name"], rows)

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory: InventoryStore | None = None) -> BuiltEvent:
        store = inventory or inventory_store
        m = self.mod
        if not hasattr(m, "load_data"):
            # Old cached stub or incomplete external module — replace with full stub API.
            m = _fedr_stub()
            self._mod = m
        args = self._build_args(store, fortisiem_ip=params.get("fortisiem_ip"), fortisiem_port=params.get("fortisiem_port"), params={**params, "ttp": event_type})
        data = m.load_data(args)
        hid = params.get("host_id")
        if hid:
            keys = {hid}
            try:
                hr = next((h for h in store.list_hosts() if h.id == hid), None)
                if hr:
                    keys.add(hr.hostname)
                    keys.add(hr.ip)
            except Exception:
                pass
            eps = [e for e in data["endpoints"] if e.get("hostname") in keys or e.get("ip") in keys]
            if eps:
                data["endpoints"] = eps
        ep = m.pick_ep(data, args.os_filter)
        reporting = m.pick_reporting(args, data)
        if params.get("reporting_host_id"):
            hh = next((h for h in store.list_hosts() if h.id == params["reporting_host_id"]), None)
            if hh:
                reporting = {"ip": hh.resolved_reporting_ip(), "name": hh.hostname}
        if event_type not in m.GEN:
            raise ValueError(f"Unknown fortiedr TTP {event_type}")
        body = m.GEN[event_type](args, data, ep)
        raw = m.syslog_msg(args, reporting, body)
        return BuiltEvent(reporting_ip=reporting["ip"], hostname=reporting["name"], payload=raw, pri=args.pri, framing=self.framing)
