# Scenario Chain

Minimal standalone tool to compose an ordered chain of synthetic syslog steps (FortiGate, Linux, Windows, FortiMail, FortiWeb, FortiProxy) and send them **one step at a time** to a FortiSIEM collector via UDP (Scapy IP spoofing).

This project lives under the CSIRT workspace by default; you can move `scenario-chain/` next to your other repos as an independent git root.

## Prerequisites

- Python 3.11+
- Node 18+ (for the UI)
- **Root/sudo** on the machine sending logs (Scapy sends raw IP with spoofed source). Use **Dry run** to test without packets.

## Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CSIRT_FORTISIEM_IP` | `10.255.9.3` | Default collector IP when the UI does not override |
| `CSIRT_FORTISIEM_PORT` | `514` | Default UDP port |

Optional `.env` in `backend/` with the same variables.

### API

- `GET /api/health` — liveness
- `GET /api/sources` — catalog: `id`, `label`, `event_types[]`
- `POST /api/step` — send one chain step (batch of `count` events)

```json
{
  "source_id": "fortigate",
  "event_type": "dns_query",
  "count": 5,
  "params": { "qname": "evil.example.com" },
  "fortisiem_ip": "10.255.9.3",
  "fortisiem_port": 514,
  "dry_run": false
}
```

Response includes `sent`, `samples` (up to 3 payload previews), `dry_run`, `status`, `reporting_ip`.

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. The Vite dev server proxies `/api` to `http://127.0.0.1:8000`.

For production build:

```bash
npm run build
```

Serve `frontend/dist/` with any static host; set `VITE_API_BASE` if the API is on another origin (empty string = same origin).

## Dry run

Set **Dry run (no UDP)** in the sticky bar or pass `"dry_run": true` in `POST /api/step`. The backend skips Scapy and returns preview payloads only.

## Inventory

Built-in synthetic hosts/users are shipped in code (`app/core/scenario_inventory.py`) — no CSV inventory files.
