from __future__ import annotations

import csv
import io
import re
import shutil
from pathlib import Path
from threading import Lock
from uuid import uuid4

from app.config import settings
from app.models.inventory import C2Row, HostRow, UserRow


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _read_csv_dicts(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if not text.strip():
        return []
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


def _write_csv_dicts(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    _ensure_parent(path)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, "") for k in fieldnames})
    path.write_text(buf.getvalue(), encoding="utf-8")


HOST_FIELDS = ["id", "hostname", "ip", "os", "os_family", "role", "reporting_ip", "group"]
USER_FIELDS = ["id", "domain", "sam", "upn", "sid", "role"]
C2_FIELDS = ["id", "ip", "domain", "country", "asn", "role"]


class InventoryStore:
    def __init__(self, data_dir: Path | None = None):
        self.data_dir = data_dir or settings.data_dir
        self.hosts_path = self.data_dir / "hosts.csv"
        self.users_path = self.data_dir / "users.csv"
        self.c2_path = self.data_dir / "c2.csv"
        self._lock = Lock()

    def bootstrap_if_empty(self) -> None:
        with self._lock:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            inst = settings.repo_root / "escenarios" / "instrumentacion"
            if not self.hosts_path.exists() or self.hosts_path.stat().st_size == 0:
                self._seed_hosts_default()
            if not self.users_path.exists() or self.users_path.stat().st_size == 0:
                ad = inst / "ad.csv"
                if ad.exists():
                    self._import_users_from_ad(ad)
                else:
                    self._seed_users_default()
            if not self.c2_path.exists() or self.c2_path.stat().st_size == 0:
                self._seed_c2_from_instrumentacion(inst)

    def _seed_hosts_default(self) -> None:
        rows = [
            {
                "id": str(uuid4()),
                "hostname": "MAD-W11-FIN-014",
                "ip": "10.0.10.30",
                "os": "Windows 11 Pro 23H2",
                "os_family": "windows",
                "role": "client",
                "reporting_ip": "10.0.10.30",
                "group": "Finance Workstations",
            },
            {
                "id": str(uuid4()),
                "hostname": "MAD-LNX-WEB-001",
                "ip": "10.0.30.21",
                "os": "Ubuntu Server 22.04 LTS",
                "os_family": "linux",
                "role": "server",
                "reporting_ip": "10.0.30.21",
                "group": "Linux Web Servers",
            },
            {
                "id": str(uuid4()),
                "hostname": "FGT-EDGE",
                "ip": "172.16.20.101",
                "os": "FortiGate 7.4",
                "os_family": "fortigate",
                "role": "firewall",
                "reporting_ip": "172.16.20.101",
                "group": "Perimeter",
            },
            {
                "id": str(uuid4()),
                "hostname": "FPX-PROXY",
                "ip": "172.16.20.102",
                "os": "FortiProxy",
                "os_family": "fortiproxy",
                "role": "firewall",
                "reporting_ip": "172.16.20.102",
                "group": "Proxy",
            },
            {
                "id": str(uuid4()),
                "hostname": "FV-WAF-01",
                "ip": "172.16.20.105",
                "os": "FortiWeb",
                "os_family": "fortiweb",
                "role": "waf",
                "reporting_ip": "172.16.20.105",
                "group": "DMZ",
            },
            {
                "id": str(uuid4()),
                "hostname": "FM-MAIL-01",
                "ip": "172.16.20.106",
                "os": "FortiMail",
                "os_family": "fortimail",
                "role": "mail_gateway",
                "reporting_ip": "172.16.20.106",
                "group": "Mail",
            },
            {
                "id": str(uuid4()),
                "hostname": "DC-MAD-01",
                "ip": "10.0.20.10",
                "os": "Windows Server 2022 DC",
                "os_family": "windows",
                "role": "domain_controller",
                "reporting_ip": "10.0.20.10",
                "group": "Domain Controllers",
            },
        ]
        _write_csv_dicts(self.hosts_path, HOST_FIELDS, rows)

    def _seed_users_default(self) -> None:
        rows = [
            {"id": str(uuid4()), "domain": "corp", "sam": "j.garcia", "upn": "j.garcia@corp.local", "sid": "", "role": ""}
        ]
        _write_csv_dicts(self.users_path, USER_FIELDS, rows)

    def _import_users_from_ad(self, path: Path) -> None:
        lines = [
            ln.strip()
            for ln in path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
        rows: list[dict[str, str]] = []
        if lines and ";" in lines[0] and not any(w in lines[0].lower() for w in ("domain", "sam", "upn")):
            for ln in lines:
                parts = [p.strip() for p in ln.split(";")]
                if len(parts) < 1 or not parts[0]:
                    continue
                sam = parts[0]
                upn = parts[1] if len(parts) > 1 else ""
                sid = parts[2] if len(parts) > 2 else ""
                domain = "corp"
                if upn and "@" in upn:
                    domain = upn.split("@", 1)[1].split(".", 1)[0].upper()
                rows.append(
                    {"id": str(uuid4()), "domain": domain, "sam": sam, "upn": upn or "", "sid": sid or "", "role": ""}
                )
        else:
            for r in _read_csv_dicts(path):
                domain = r.get("domain") or "corp"
                sam = r.get("sam") or r.get("username") or ""
                upn = r.get("upn") or r.get("userPrincipalName") or ""
                sid = r.get("sid") or ""
                if sam:
                    rows.append({"id": str(uuid4()), "domain": domain, "sam": sam, "upn": upn, "sid": sid, "role": r.get("role", "")})
        if not rows:
            self._seed_users_default()
            return
        _write_csv_dicts(self.users_path, USER_FIELDS, rows)

    def _seed_c2_from_instrumentacion(self, inst: Path) -> None:
        rows: list[dict[str, str]] = []
        atk = inst / "attackers.txt"
        if atk.exists():
            for ln in atk.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                ip = re.split(r"[;,]", ln)[0].strip()
                if ip:
                    rows.append(
                        {
                            "id": str(uuid4()),
                            "ip": ip,
                            "domain": "",
                            "country": "N/A",
                            "asn": "N/A",
                            "role": "attacker",
                        }
                    )
        c2f = inst / "c2c.txt"
        if c2f.exists():
            for ln in c2f.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                parts = [p.strip() for p in re.split(r"[;,]", ln) if p.strip()]
                if not parts:
                    continue
                val = parts[0]
                ip = ""
                domain = ""
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val):
                    ip = val
                elif "." in val:
                    domain = val
                rows.append(
                    {
                        "id": str(uuid4()),
                        "ip": ip or "93.184.216.34",
                        "domain": domain or ("unknown.example.net" if ip else val),
                        "country": "N/A",
                        "asn": "N/A",
                        "role": "c2",
                    }
                )
        if not rows:
            rows.append(
                {
                    "id": str(uuid4()),
                    "ip": "185.231.88.45",
                    "domain": "evil-example.com",
                    "country": "N/A",
                    "asn": "N/A",
                    "role": "attacker",
                }
            )
        _write_csv_dicts(self.c2_path, C2_FIELDS, rows)

    # --- CRUD hosts ---
    def list_hosts(self) -> list[HostRow]:
        rows = _read_csv_dicts(self.hosts_path)
        out = []
        for r in rows:
            if not r.get("hostname"):
                continue
            rid = r.get("id") or str(uuid4())
            out.append(
                HostRow(
                    id=rid,
                    hostname=r["hostname"],
                    ip=r.get("ip", ""),
                    os=r.get("os", ""),
                    os_family=r.get("os_family", "linux"),
                    role=r.get("role", ""),
                    reporting_ip=r.get("reporting_ip") or None,
                    group=r.get("group", ""),
                )
            )
        return out

    def upsert_host(self, row: HostRow) -> HostRow:
        with self._lock:
            rows = _read_csv_dicts(self.hosts_path)
            rid = row.id or str(uuid4())
            new_d = {
                "id": rid,
                "hostname": row.hostname,
                "ip": row.ip,
                "os": row.os,
                "os_family": row.os_family,
                "role": row.role,
                "reporting_ip": row.reporting_ip or "",
                "group": row.group,
            }
            replaced = False
            for i, r in enumerate(rows):
                if r.get("id") == rid or r.get("hostname") == row.hostname:
                    rows[i] = new_d
                    replaced = True
                    break
            if not replaced:
                rows.append(new_d)
            _write_csv_dicts(self.hosts_path, HOST_FIELDS, rows)
        return HostRow(**new_d)

    def delete_host(self, hid: str) -> bool:
        with self._lock:
            rows = _read_csv_dicts(self.hosts_path)
            new_rows = [r for r in rows if r.get("id") != hid and r.get("hostname") != hid]
            if len(new_rows) == len(rows):
                return False
            _write_csv_dicts(self.hosts_path, HOST_FIELDS, new_rows)
        return True

    # --- users ---
    def list_users(self) -> list[UserRow]:
        rows = _read_csv_dicts(self.users_path)
        out = []
        for r in rows:
            sam = r.get("sam") or r.get("username") or ""
            if not sam:
                continue
            out.append(
                UserRow(
                    id=r.get("id") or str(uuid4()),
                    domain=r.get("domain", "corp"),
                    sam=sam,
                    upn=r.get("upn"),
                    sid=r.get("sid"),
                    role=r.get("role"),
                )
            )
        return out

    def upsert_user(self, row: UserRow) -> UserRow:
        with self._lock:
            rows = _read_csv_dicts(self.users_path)
            rid = row.id or str(uuid4())
            new_d = {
                "id": rid,
                "domain": row.domain,
                "sam": row.sam,
                "upn": row.upn or "",
                "sid": row.sid or "",
                "role": row.role or "",
            }
            replaced = False
            for i, r in enumerate(rows):
                if r.get("id") == rid or r.get("sam") == row.sam:
                    rows[i] = new_d
                    replaced = True
                    break
            if not replaced:
                rows.append(new_d)
            _write_csv_dicts(self.users_path, USER_FIELDS, rows)
        return UserRow(**new_d)

    def delete_user(self, uid: str) -> bool:
        with self._lock:
            rows = _read_csv_dicts(self.users_path)
            new_rows = [r for r in rows if r.get("id") != uid and r.get("sam") != uid]
            if len(new_rows) == len(rows):
                return False
            _write_csv_dicts(self.users_path, USER_FIELDS, new_rows)
        return True

    # --- c2 ---
    def list_c2(self) -> list[C2Row]:
        rows = _read_csv_dicts(self.c2_path)
        out = []
        for r in rows:
            out.append(
                C2Row(
                    id=r.get("id") or str(uuid4()),
                    ip=r.get("ip", ""),
                    domain=r.get("domain", ""),
                    country=r.get("country", "N/A"),
                    asn=r.get("asn", "N/A"),
                    role=r.get("role", "c2"),
                )
            )
        return out

    def upsert_c2(self, row: C2Row) -> C2Row:
        with self._lock:
            rows = _read_csv_dicts(self.c2_path)
            rid = row.id or str(uuid4())
            new_d = {
                "id": rid,
                "ip": row.ip,
                "domain": row.domain,
                "country": row.country,
                "asn": row.asn,
                "role": row.role,
            }
            replaced = False
            key = (row.ip, row.domain, row.role)
            for i, r in enumerate(rows):
                rk = (r.get("ip", ""), r.get("domain", ""), r.get("role", "c2"))
                if r.get("id") == rid or rk == key:
                    rows[i] = new_d
                    replaced = True
                    break
            if not replaced:
                rows.append(new_d)
            _write_csv_dicts(self.c2_path, C2_FIELDS, rows)
        return C2Row(**new_d)

    def delete_c2(self, cid: str) -> bool:
        with self._lock:
            rows = _read_csv_dicts(self.c2_path)
            new_rows = [r for r in rows if r.get("id") != cid]
            if len(new_rows) == len(rows):
                return False
            _write_csv_dicts(self.c2_path, C2_FIELDS, new_rows)
        return True

    def export_hosts_bytes(self) -> bytes:
        return self.hosts_path.read_bytes() if self.hosts_path.exists() else b""

    def import_hosts_replace(self, content: bytes) -> None:
        with self._lock:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.data_dir / ".hosts.import.tmp"
            tmp.write_bytes(content)
            shutil.move(str(tmp), str(self.hosts_path))


inventory_store = InventoryStore()
