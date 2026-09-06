"""
SQLite persistence for the standalone app.

One table: engagements, storing each engagement (its ROE, built plan, and
documentation) as a JSON blob. That is all Siege Tower ever stores — what the
team types. It holds no data taken from a client's systems, and nothing here
runs anything. SQLite keeps the app dependency-free and self-contained.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

_DB_PATH = os.environ.get("SIEGE_DB", str(Path(__file__).resolve().parent.parent / "siege.db"))


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(_DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS engagements (
                   id TEXT PRIMARY KEY,
                   data TEXT NOT NULL,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL
               )"""
        )


def _now() -> str:
    return datetime.utcnow().isoformat()


def create_engagement(data: dict) -> dict:
    eid = str(uuid.uuid4())
    now = _now()
    data = {**data, "id": eid, "created_at": now, "updated_at": now}
    with _conn() as c:
        c.execute(
            "INSERT INTO engagements (id, data, created_at, updated_at) VALUES (?,?,?,?)",
            (eid, json.dumps(data), now, now),
        )
    return data


def get_engagement(eid: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT data FROM engagements WHERE id=?", (eid,)).fetchone()
    return json.loads(row["data"]) if row else None


def update_engagement(eid: str, data: dict) -> dict | None:
    existing = get_engagement(eid)
    if not existing:
        return None
    now = _now()
    merged = {**existing, **data, "id": eid,
              "created_at": existing.get("created_at", now), "updated_at": now}
    with _conn() as c:
        c.execute("UPDATE engagements SET data=?, updated_at=? WHERE id=?",
                  (json.dumps(merged), now, eid))
    return merged


def delete_engagement(eid: str) -> bool:
    with _conn() as c:
        cur = c.execute("DELETE FROM engagements WHERE id=?", (eid,))
        return cur.rowcount > 0


def list_engagements() -> list[dict]:
    with _conn() as c:
        rows = c.execute("SELECT data FROM engagements ORDER BY updated_at DESC").fetchall()
    return [json.loads(r["data"]) for r in rows]
