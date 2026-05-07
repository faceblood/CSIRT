from __future__ import annotations

import random

from .models import Template


def select_template(templates: list[Template], source: str, category: str, hint: str) -> Template | None:
    filtered = [t for t in templates if t.source == source and t.category == category]
    if not filtered:
        return None
    exact = [t for t in filtered if t.event_name.lower() == hint.lower()]
    pool = exact if exact else [t for t in filtered if hint.lower() in t.event_name.lower()]
    if not pool:
        pool = filtered
    return random.choices(pool, weights=[max(1, t.weight) for t in pool], k=1)[0]
