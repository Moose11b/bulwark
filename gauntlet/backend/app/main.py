"""Gauntlet API + facilitator console host."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api import environments, reports, scenarios, sessions
from .config import APP_TAGLINE, APP_TITLE, SEED_ON_START, WEB_DIR
from .database import SessionLocal, create_all


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_all()
    if SEED_ON_START:
        db = SessionLocal()
        try:
            from .seed import seed_if_empty

            seed_if_empty(db)
        finally:
            db.close()
    yield


app = FastAPI(
    title=APP_TITLE,
    description=f"{APP_TAGLINE}. Tabletop-first reference implementation.",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok", "app": APP_TITLE, "version": __version__}


app.include_router(environments.router)
app.include_router(scenarios.router)
app.include_router(sessions.router)
app.include_router(reports.router)

# Facilitator console (served last so it never shadows the API routes).
if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="console")
