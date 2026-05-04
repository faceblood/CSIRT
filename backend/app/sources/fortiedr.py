from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from app.config import settings
from app.core.inventory_store import InventoryStore, inventory_store
from app.sources.base import BuiltEvent, EventTypeSpec, Framing


def _fedr_stub():
    """Minimal stand-in when the external script is missing or cannot register signals (non-main thread)."""
    return SimpleNamespace(GEN={"ransomware": {}, "stub_edr": {}})


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


def _write_endpoints_csv(store: InventoryStore, out: Path) -> None:
    rows = []
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
    import csv

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["hostname", "ip", "os", "os_family", "group"])
        w.writeheader()
        for r in rows:
            w.writerow(r)


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
        endpoints_path = ddir / "_generated_endpoints.csv"
        _write_endpoints_csv(store, endpoints_path)
        inst = settings.repo_root / "escenarios" / "instrumentacion"
        proc = inst / "processes.csv"
        proc_path = str(proc) if proc.exists() else "/nonexistent/processes.csv"
        rep_pool = ddir / "_generated_reporting.csv"
        self._ensure_reporting_csv(store, rep_pool)
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

    def _ensure_reporting_csv(self, store: InventoryStore, path: Path) -> None:
        # Use FortiEDR-like collector hosts if present, else first non-appliance IP
        collectors = [h for h in store.list_hosts() if "fortiedr" in (h.group or "").lower() or "edr" in (h.role or "").lower()]
        rows = []
        for h in collectors or store.list_hosts()[:3]:
            rows.append({"ip": h.resolved_reporting_ip(), "name": h.hostname})
        if not rows:
            rows.append({"ip": "172.16.20.110", "name": "FORTIEDR-CM-01"})
        import csv

        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["ip", "name"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

    def build_event(self, *, event_type: str, params: dict[str, Any], inventory: InventoryStore | None = None) -> BuiltEvent:
        store = inventory or inventory_store
        m = self.mod
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
