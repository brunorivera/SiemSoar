"""FastAPI backend for the SIEM/SOAR thesis prototype.

Run from ``prototype_ui/``:

    python run.py
    # or
    python -m uvicorn backend.app:app --port 8000

The backend also serves ``frontend/`` at ``/`` so the demo needs a single
process. All API responses are JSON.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db, engine

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="SIEM & SOAR — Prototipo de tesis",
    description=(
        "Prototipo funcional del pipeline de ingesta, correlación por ventana "
        "deslizante, generación de alertas y respuesta activa con TTL. "
        "Datos en SQLite; no modifica el laboratorio n8n/PostgreSQL."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class IngestRequest(BaseModel):
    scenario: str = Field(
        default="custom",
        description=(
            "ssh_bruteforce | port_scan | sqli | root_login | sudo_abuse | benign | custom"
        ),
    )
    events: Optional[list[str]] = Field(
        default=None,
        description="Líneas de log crudas para scenario=custom.",
    )
    source_ip: Optional[str] = Field(
        default=None,
        description="IP de origen a usar en el escenario (si se omite, se elige una de prueba).",
    )
    count: Optional[int] = Field(default=None, ge=1, le=200)
    source: Optional[str] = Field(
        default=None,
        description="Pista de fuente para eventos custom (auth.log, apache_access/all.log, ...).",
    )
    run_cycle: bool = Field(
        default=False,
        description="Ejecutar un ciclo de correlación inmediatamente después de la ingesta.",
    )


class RunCycleRequest(BaseModel):
    trigger: str = "manual"
    arm: str = "prototype"


class UnblockRequest(BaseModel):
    ip: str


class IngestResponse(BaseModel):
    ok: bool
    scenario: str
    meta: dict
    ingest: dict
    cycle: Optional[dict] = None


@app.get("/api/health", tags=["system"])
def health() -> dict:
    with db.get_conn() as conn:
        return engine.health(conn)


@app.post("/api/ingest", response_model=IngestResponse, tags=["pipeline"])
def ingest(payload: IngestRequest) -> dict:
    """Ingest raw log lines or generate a named attack/benign scenario."""
    scenario = (payload.scenario or "custom").strip().lower()

    if payload.events:
        records = [
            (line, engine.now_utc(), payload.source)
            for line in payload.events
            if isinstance(line, str) and line.strip()
        ]
        if not records:
            raise HTTPException(status_code=400, detail="events[] no contiene líneas válidas.")
        meta = {
            "scenario": "custom",
            "label": "Ingesta manual de líneas",
            "source_ip": payload.source_ip,
            "events": len(records),
            "spacing_seconds": 0,
            "note": "Las líneas se evalúan con el timestamp de ingesta (ahora, UTC).",
        }
    else:
        try:
            records, meta = engine.build_scenario(
                scenario, source_ip=payload.source_ip, count=payload.count
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    with db.get_conn() as conn:
        result = engine.ingest_records(conn, records)

    cycle = None
    if payload.run_cycle:
        with db.get_conn() as conn:
            cycle = engine.run_cycle(conn, trigger=f"ingest:{meta['scenario']}")

    return {
        "ok": True,
        "scenario": meta["scenario"],
        "meta": meta,
        "ingest": result,
        "cycle": cycle,
    }


@app.post("/api/run-cycle", tags=["pipeline"])
def run_cycle(payload: Optional[RunCycleRequest] = None) -> dict:
    """Run one pipeline cycle: correlate -> alert -> decide -> block -> log."""
    trigger = payload.trigger if payload else "manual"
    arm = payload.arm if payload else "prototype"
    with db.get_conn() as conn:
        summary = engine.run_cycle(conn, trigger=trigger, arm=arm)
    return {"ok": True, "cycle": summary}


@app.get("/api/dashboard", tags=["dashboard"])
def dashboard() -> dict:
    """Aggregated live state for the four frontend panels."""
    with db.get_conn() as conn:
        return engine.dashboard(conn)


@app.post("/api/unblock", tags=["response"])
def unblock(payload: UnblockRequest) -> dict:
    """Manually remove an active block (R6)."""
    try:
        with db.get_conn() as conn:
            return engine.unblock(conn, payload.ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/reset", tags=["system"])
def reset() -> dict:
    """Reset demo data (events, alerts, runs, blocks) while keeping rules."""
    db.reset_demo()
    return {"ok": True, "message": "Datos de demostración reiniciados; reglas conservadas."}


@app.get("/api/rules", tags=["pipeline"])
def rules() -> dict:
    """The five detection rules loaded in the catalogue (Table 7)."""
    with db.get_conn() as conn:
        loaded = engine.load_rules(conn)
    return {
        "ok": True,
        "rules": [
            {
                "id": rule["id"],
                "name": rule["name"],
                "description": rule["description"],
                "pattern": rule["pattern"],
                "severity": rule["severity"],
                "threshold": rule["threshold"],
                "time_window": rule["time_window"],
                "category": rule["category"],
                "action": rule["action"],
            }
            for rule in loaded
        ],
    }


# Static frontend last, so /api/* keeps priority over the catch-all mount.
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
