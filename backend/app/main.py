import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.core.history import HistoryBuffer
from app.core.inventory_store import inventory_store
from app.core.exercise_store import exercise_store
from app.core.jobs import init_job_manager
from app.routers import bulk, catalog, exercise, generate, history, inventory, jobs, keepalive, playbook, raw, simulate, upload


@asynccontextmanager
async def lifespan(app: FastAPI):
    inventory_store.bootstrap_if_empty()
    exercise_store.seed_defaults()
    hist = HistoryBuffer(maxlen=settings.history_limit)
    app.state.history = hist
    init_job_manager(hist, asyncio.get_running_loop())
    yield


app = FastAPI(title="FortiSIEM TTP / TTX Simulator", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    import os

    root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import scapy  # noqa: F401

        scapy_ok = True
    except Exception:
        scapy_ok = False
    return {
        "ok": True,
        "root": root,
        "scapy_available": scapy_ok,
        "fortisiem_ip": settings.fortisiem_ip,
        "fortisiem_port": settings.fortisiem_port,
        "history_limit": settings.history_limit,
    }


app.include_router(inventory.router)
app.include_router(catalog.router)
app.include_router(generate.router)
app.include_router(raw.router)
app.include_router(bulk.router)
app.include_router(simulate.router)
app.include_router(upload.router)
app.include_router(history.router)
app.include_router(jobs.router)
app.include_router(playbook.router)
app.include_router(keepalive.router)
app.include_router(exercise.router)

static_dir = settings.repo_root / "frontend" / "dist"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
else:

    @app.get("/")
    def root_api_only():
        """Avoid bare `/` returning opaque 404 when the SPA has not been built."""
        return {
            "service": app.title,
            "openapi": "/openapi.json",
            "docs": "/docs",
            "health": "/api/health",
            "hint": "Run `npm run build` in frontend/ and restart so `/` serves the UI.",
        }
