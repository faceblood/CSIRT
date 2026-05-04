# FortiSIEM TTP / TTX log simulator

FastAPI backend plus optional React UI for spoofed-source UDP syslog toward FortiSIEM (Scapy), with inventory CSVs, condensed APT playbook, keepalive baseline, multi-source simulate jobs, exercise JSON scenarios, and bulk/raw uploads.

## Requirements

- **Python 3.10+** recommended. **Python 3.9** is supported via postponed annotations plus **`eval-type-backport`** (listed in `backend/requirements.txt` for Pydantic).
- **Node.js 18+** for the frontend dev server and production build.
- Run traffic injection **as root** when kernel raw/socket privileges are required for source IP spoofing (same constraint as the original Scapy scripts).

## Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
sudo .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Configure collector IP/port via environment **`CSIRT_FORTISIEM_IP`** / **`CSIRT_FORTISIEM_PORT`**, or `backend/app/config.py` (defaults align with lab scripts such as `10.255.9.3:514`). Background jobs (**playbook**, **keepalive**, **simulate**, **exercise run**) accept optional **`fortisiem_ip`** / **`fortisiem_port`** on their start payloads to override the server default for that job only (also visible under **`meta`** on **`GET /api/jobs/{id}`**).

Data paths:

- Inventory CSVs under `data/inventory/` (bootstrapped from `escenarios/instrumentacion/` when empty).
- Exercise definitions under `data/exercises/` (`backend/app/exercises/seeds/` seeds the water OT TTX sample when the folder is empty).

### Useful HTTP endpoints

| Area | Method | Path |
|------|--------|------|
| Health | GET | `/api/health` |
| Sources / campaigns | GET | `/api/sources`, `/api/campaigns` |
| Inventory | CRUD | `/api/inventory/hosts`, `/users`, `/c2` |
| Single event | POST | `/api/generate` |
| Raw / bulk lines | POST | `/api/raw`, `/api/bulk` |
| File upload (lines) | POST | `/api/upload` (multipart) |
| Multi-source job | POST | `/api/simulate` → `{ "job_id" }` |
| Job control | POST | `/api/jobs/{id}/pause`, `/resume`, `/stop`, `/skip-inject`, `/jump-inject` (body `{"inject_idx": N}` — exercise only) |
| Exercises | CRUD | `/api/exercises`, `GET /api/exercises/{id}/timeline`, `POST /api/exercises/{id}/run` |
| History | GET | `/api/history` |

With a built frontend, static files from `frontend/dist` are served from `/` when that directory exists.

## CI (GitHub Actions)

On pushes and pull requests to **`main`**, workflows run **backend** [`pytest`](backend/tests/test_smoke.py) and **frontend** **`npm run build`** (TypeScript + Vite). [Dependabot](.github/dependabot.yml) opens weekly grouped updates for **`backend/`** (pip) and **`frontend/`** (npm).

## Testing (backend smoke)

```bash
cd backend
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Dev server port defaults to **5173**. Override with **`VITE_DEV_PORT`** / **`PORT`**, or **`npm run dev -- --port 3389`** (CLI wins over env). Vite proxies `/api` to `http://127.0.0.1:8000`. Production build:

```bash
npm run build
```

Then serve the API with `frontend/dist` present so the SPA is mounted by FastAPI.

## License / use

Lab and tabletops only; ensure you have authorization before sending traffic to any collector.
