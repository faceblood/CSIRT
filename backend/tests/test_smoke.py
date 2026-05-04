"""Lightweight API smoke tests — run from `backend/` with pytest."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client() -> TestClient:
    from app.main import app

    with TestClient(app) as c:
        yield c


def test_health(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "fortisiem_ip" in data
    assert "fortisiem_port" in data


def test_sources_catalog(client: TestClient) -> None:
    r = client.get("/api/sources")
    assert r.status_code == 200
    rows = r.json()
    assert isinstance(rows, list)
    assert len(rows) >= 1
    assert "id" in rows[0]
    assert "event_types" in rows[0]


def test_campaigns(client: TestClient) -> None:
    r = client.get("/api/campaigns")
    assert r.status_code == 200
    camps = r.json()
    assert isinstance(camps, list)
    assert any(c.get("id") == "apt_mitre" for c in camps)


def test_inventory_hosts(client: TestClient) -> None:
    r = client.get("/api/inventory/hosts")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_exercises_list(client: TestClient) -> None:
    r = client.get("/api/exercises")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_simulate_validation_empty_plan(client: TestClient) -> None:
    r = client.post("/api/simulate", json={"plan": []})
    assert r.status_code == 400
