"""Runtime configuration.

Zero-infrastructure by default: a local SQLite file so the whole product runs
with nothing but Python. Override with the ``GAUNTLET_*`` environment variables
to point at Postgres or relocate the database.
"""
from __future__ import annotations

import os
from pathlib import Path

# Repo-root/gauntlet/backend/app/config.py -> gauntlet/backend
BACKEND_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BACKEND_DIR.parent / "web"

DB_URL = os.environ.get(
    "GAUNTLET_DB_URL",
    f"sqlite:///{BACKEND_DIR / 'gauntlet.db'}",
)

# When true, a worked example (finance ransomware tabletop) is loaded on an
# empty database so a fresh checkout has something to run immediately.
SEED_ON_START = os.environ.get("GAUNTLET_SEED", "1") not in ("0", "false", "False")

APP_TITLE = "Gauntlet"
APP_TAGLINE = "Security exercise design & proctoring"
