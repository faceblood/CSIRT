from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from threading import Lock

from app.config import settings


OFFSET_RE = re.compile(r"^\s*(?P<sign>[+-]?)(?P<num>\d+)\s*(?P<unit>h|m|s)?\s*$", re.I)


def parse_offset(s: str):
    from datetime import timedelta

    s = str(s).strip().lower().replace(" ", "")
    if s in ("0", "+0", "-0"):
        return timedelta(0)
    if s.endswith("h") or "_h" in s:
        # allow legacy "-2h"
        m = re.match(r"^([+-]?)(\d+)h$", s)
        if m:
            sign = -1 if m.group(1) == "-" else 1
            return timedelta(hours=sign * int(m.group(2)))
    if s.endswith("m"):
        m = re.match(r"^([+-]?)(\d+)m$", s)
        if m:
            sign = -1 if m.group(1) == "-" else 1
            return timedelta(minutes=sign * int(m.group(2)))
    if s.endswith("s"):
        m = re.match(r"^([+-]?)(\d+)s$", s)
        if m:
            sign = -1 if m.group(1) == "-" else 1
            return timedelta(seconds=sign * int(m.group(2)))
    mo = OFFSET_RE.match(s)
    if mo:
        sign = -1 if mo.group("sign") == "-" else 1
        num = int(mo.group("num"))
        unit = mo.group("unit") or "s"
        if unit == "h":
            return timedelta(hours=sign * num)
        if unit == "m":
            return timedelta(minutes=sign * num)
        return timedelta(seconds=sign * num)
    raise ValueError(f"Bad offset {s!r}")


class ExerciseStore:
    def __init__(self, root: Path | None = None):
        self.root = root or (settings.data_dir / settings.exercises_dir_name)
        self._lock = Lock()

    def ensure_dir(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def seed_defaults(self) -> None:
        self.ensure_dir()
        if any(self.root.glob("*.json")):
            return
        seeds_dir = Path(__file__).resolve().parent.parent / "exercises" / "seeds"
        if seeds_dir.exists():
            for p in seeds_dir.glob("*.json"):
                shutil.copy(p, self.root / p.name)

    def list_ids(self) -> list[str]:
        self.ensure_dir()
        return sorted([p.stem for p in self.root.glob("*.json")])

    def load(self, exercise_id: str) -> dict:
        path = self.root / f"{exercise_id}.json"
        if not path.exists():
            raise FileNotFoundError(exercise_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def save(self, exercise_id: str, doc: dict) -> None:
        self.ensure_dir()
        path = self.root / f"{exercise_id}.json"
        with self._lock:
            path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")

    def delete(self, exercise_id: str) -> bool:
        path = self.root / f"{exercise_id}.json"
        if not path.exists():
            return False
        path.unlink()
        return True


exercise_store = ExerciseStore()
