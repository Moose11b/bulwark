"""
SQLite persistence for the standalone app.

Tables:
  * orgs         — a tenant (a client workspace / consulting practice)
  * users        — accounts, scoped to an org, with a role
  * sessions     — opaque bearer tokens (stored only as a hash) with expiry
  * engagements  — the ROE + plan + documentation, an encrypted JSON blob,
                   scoped to an org and soft-deleted (never silently destroyed)
  * audit_log    — append-only record of who did what, when

The engagement blob holds only what the team types (client names, in-scope
targets, notes, evidence references). It never contains data taken from a
client's systems, and nothing here runs anything. The blob is encrypted at rest
when SIEGE_ENCRYPTION_KEY is configured (see server.security.Encryptor).

Every query that returns engagements is scoped by org_id — a caller can only
ever see its own tenant's data. That separation is enforced here, in the data
layer, not left to the routes.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .security import Encryptor, hash_password, hash_token, new_token

_DB_PATH = os.environ.get(
    "SIEGE_DB", str(Path(__file__).resolve().parent.parent / "siege.db")
)

# Session lifetime; refreshed on use (sliding expiry).
SESSION_TTL = timedelta(hours=int(os.environ.get("SIEGE_SESSION_TTL_HOURS", "12")))

_ENC = Encryptor()

VALID_ROLES = ("admin", "operator", "viewer")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(_DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA journal_mode = WAL")
    return c


def init_db() -> None:
    with _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS orgs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                username TEXT NOT NULL UNIQUE,
                email TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                is_active INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS engagements (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                deleted_at TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                engagement_id TEXT REFERENCES engagements(id) ON DELETE CASCADE,
                created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                deleted_at TEXT
            );
            CREATE TABLE IF NOT EXISTS finding_library (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                deleted_at TEXT
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                engagement_id TEXT REFERENCES engagements(id) ON DELETE CASCADE,
                finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
                uploaded_by TEXT REFERENCES users(id) ON DELETE SET NULL,
                meta TEXT NOT NULL,
                content_type TEXT,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                deleted_at TEXT
            );
            CREATE TABLE IF NOT EXISTS engagement_templates (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                deleted_at TEXT
            );
            CREATE TABLE IF NOT EXISTS shares (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
                label TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                actor_id TEXT,
                org_id TEXT,
                action TEXT NOT NULL,
                target_id TEXT,
                ip TEXT,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_eng_org ON engagements(org_id);
            CREATE INDEX IF NOT EXISTS idx_find_org ON findings(org_id);
            CREATE INDEX IF NOT EXISTS idx_find_eng ON findings(engagement_id);
            CREATE INDEX IF NOT EXISTS idx_lib_org ON finding_library(org_id);
            CREATE INDEX IF NOT EXISTS idx_ev_org ON evidence(org_id);
            CREATE INDEX IF NOT EXISTS idx_ev_eng ON evidence(engagement_id);
            CREATE INDEX IF NOT EXISTS idx_ev_find ON evidence(finding_id);
            CREATE INDEX IF NOT EXISTS idx_shares_eng ON shares(engagement_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id);
            """
        )
        # Lightweight migrations for pre-existing databases.
        org_cols = [r[1] for r in c.execute("PRAGMA table_info(orgs)").fetchall()]
        if "branding" not in org_cols:
            c.execute("ALTER TABLE orgs ADD COLUMN branding TEXT")
        user_cols = [r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()]
        if "must_change_password" not in user_cols:
            c.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")


# ── Orgs & users ─────────────────────────────────────────────────

def create_org(name: str) -> dict:
    oid = _new_id()
    now = _now()
    with _conn() as c:
        c.execute(
            "INSERT INTO orgs (id, name, created_at) VALUES (?,?,?)", (oid, name, now)
        )
    return {"id": oid, "name": name, "created_at": now}


def get_org(org_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM orgs WHERE id=?", (org_id,)).fetchone()
    return {"id": row["id"], "name": row["name"], "created_at": row["created_at"]} if row else None


def get_branding(org_id: str) -> dict:
    with _conn() as c:
        row = c.execute("SELECT branding FROM orgs WHERE id=?", (org_id,)).fetchone()
    if row and row["branding"]:
        try:
            return json.loads(row["branding"])
        except ValueError:
            return {}
    return {}


def set_branding(org_id: str, data: dict) -> dict:
    merged = {**get_branding(org_id), **data}
    # Drop keys explicitly set to None (a way to clear a field).
    merged = {k: v for k, v in merged.items() if v is not None}
    with _conn() as c:
        c.execute("UPDATE orgs SET branding=? WHERE id=?", (json.dumps(merged), org_id))
    return merged


def first_org() -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM orgs ORDER BY created_at LIMIT 1").fetchone()
    return {"id": row["id"], "name": row["name"], "created_at": row["created_at"]} if row else None


def count_users() -> int:
    with _conn() as c:
        return c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]


def create_user(
    org_id: str, username: str, password: str, role: str = "operator",
    email: str | None = None, must_change: bool = False,
) -> dict:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}")
    uid = _new_id()
    now = _now()
    pwd = hash_password(password)  # raises on weak passwords
    with _conn() as c:
        c.execute(
            """INSERT INTO users
               (id, org_id, username, email, password_hash, role, is_active,
                must_change_password, created_at)
               VALUES (?,?,?,?,?,?,1,?,?)""",
            (uid, org_id, username, email, pwd, role, 1 if must_change else 0, now),
        )
    return get_user(uid)


def get_user(uid: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return _user_row(row)


def get_user_by_username(username: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return _user_row(row)


def list_users(org_id: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM users WHERE org_id=? ORDER BY created_at", (org_id,)
        ).fetchall()
    return [_user_row(r) for r in rows]


def update_user(uid: str, org_id: str, *, role: str | None = None,
                is_active: bool | None = None, password: str | None = None) -> dict | None:
    existing = get_user(uid)
    if not existing or existing["org_id"] != org_id:
        return None
    sets, vals = [], []
    if role is not None:
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role}")
        sets.append("role=?"); vals.append(role)
    if is_active is not None:
        sets.append("is_active=?"); vals.append(1 if is_active else 0)
    if password is not None:
        sets.append("password_hash=?"); vals.append(hash_password(password))
    if not sets:
        return existing
    vals.append(uid)
    with _conn() as c:
        c.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", vals)
        if password is not None:
            # New password → revoke every existing session for that user.
            c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    return get_user(uid)


def set_password(uid: str, password: str) -> None:
    """Set a password chosen by the user — clears any forced-change flag."""
    with _conn() as c:
        c.execute(
            "UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
            (hash_password(password), uid),
        )
        c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))


def admin_reset_password(uid: str, org_id: str) -> str | None:
    """Reset a user's password to a strong temp value (same org only), forcing a
    change on next login. Returns the temp password once, or None if not found."""
    import secrets
    user = get_user(uid)
    if not user or user["org_id"] != org_id:
        return None
    temp = secrets.token_urlsafe(12)
    with _conn() as c:
        c.execute(
            "UPDATE users SET password_hash=?, must_change_password=1 WHERE id=? AND org_id=?",
            (hash_password(temp), uid, org_id),
        )
        c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    return temp


def mark_login(uid: str) -> None:
    with _conn() as c:
        c.execute("UPDATE users SET last_login_at=? WHERE id=?", (_now(), uid))


def _user_row(row: sqlite3.Row | None) -> dict | None:
    if not row:
        return None
    return {
        "id": row["id"], "org_id": row["org_id"], "username": row["username"],
        "email": row["email"], "role": row["role"],
        "is_active": bool(row["is_active"]), "created_at": row["created_at"],
        "last_login_at": row["last_login_at"], "password_hash": row["password_hash"],
        "must_change_password": bool(row["must_change_password"]),
    }


# ── Sessions (bearer tokens) ─────────────────────────────────────

def create_session(user_id: str) -> str:
    """Issue a token; only its hash is stored. Returns the plaintext token."""
    token = new_token()
    now = datetime.now(timezone.utc)
    with _conn() as c:
        c.execute(
            """INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at)
               VALUES (?,?,?,?,?)""",
            (hash_token(token), user_id, now.isoformat(),
             (now + SESSION_TTL).isoformat(), now.isoformat()),
        )
    return token


def resolve_session(token: str) -> dict | None:
    """Return the user for a valid, unexpired token; refresh sliding expiry."""
    th = hash_token(token)
    now = datetime.now(timezone.utc)
    with _conn() as c:
        row = c.execute("SELECT * FROM sessions WHERE token_hash=?", (th,)).fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) < now:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
            return None
        c.execute(
            "UPDATE sessions SET last_used_at=?, expires_at=? WHERE token_hash=?",
            (now.isoformat(), (now + SESSION_TTL).isoformat(), th),
        )
        user = c.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
    u = _user_row(user)
    if not u or not u["is_active"]:
        return None
    return u


def revoke_session(token: str) -> None:
    with _conn() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (hash_token(token),))


def purge_expired_sessions() -> None:
    with _conn() as c:
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (_now(),))


# ── Engagements (tenant-scoped, encrypted, soft-deleted) ─────────

def _encode(data: dict) -> str:
    return _ENC.encrypt(json.dumps(data))


def _decode(blob: str) -> dict:
    return json.loads(_ENC.decrypt(blob))


def create_engagement(org_id: str, created_by: str, data: dict) -> dict:
    eid = _new_id()
    now = _now()
    body = {k: v for k, v in data.items()
            if k not in ("id", "created_at", "updated_at", "org_id", "created_by")}
    body = {**body, "id": eid, "created_at": now, "updated_at": now}
    with _conn() as c:
        c.execute(
            """INSERT INTO engagements
               (id, org_id, created_by, data, created_at, updated_at)
               VALUES (?,?,?,?,?,?)""",
            (eid, org_id, created_by, _encode(body), now, now),
        )
    return body


def get_engagement(eid: str, org_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT data FROM engagements WHERE id=? AND org_id=? AND deleted_at IS NULL",
            (eid, org_id),
        ).fetchone()
    return _decode(row["data"]) if row else None


def update_engagement(eid: str, org_id: str, data: dict) -> dict | None:
    existing = get_engagement(eid, org_id)
    if not existing:
        return None
    now = _now()
    incoming = {k: v for k, v in data.items()
                if k not in ("id", "created_at", "org_id", "created_by")}
    merged = {**existing, **incoming, "id": eid,
              "created_at": existing.get("created_at", now), "updated_at": now}
    with _conn() as c:
        c.execute(
            "UPDATE engagements SET data=?, updated_at=? WHERE id=? AND org_id=?",
            (_encode(merged), now, eid, org_id),
        )
    return merged


def delete_engagement(eid: str, org_id: str) -> bool:
    """Soft delete — the row is retained (retention / chain-of-custody)."""
    with _conn() as c:
        cur = c.execute(
            "UPDATE engagements SET deleted_at=? WHERE id=? AND org_id=? AND deleted_at IS NULL",
            (_now(), eid, org_id),
        )
        return cur.rowcount > 0


def purge_engagement(eid: str, org_id: str) -> bool:
    """Hard delete — admin-only, irreversible. Used for right-to-erasure."""
    with _conn() as c:
        cur = c.execute(
            "DELETE FROM engagements WHERE id=? AND org_id=?", (eid, org_id)
        )
        return cur.rowcount > 0


def list_engagements(org_id: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT data FROM engagements WHERE org_id=? AND deleted_at IS NULL "
            "ORDER BY updated_at DESC",
            (org_id,),
        ).fetchall()
    return [_decode(r["data"]) for r in rows]


# ── Findings (tenant-scoped, encrypted, soft-deleted) ────────────

def create_finding(org_id: str, created_by: str, engagement_id: str | None,
                   data: dict) -> dict:
    fid = _new_id()
    now = _now()
    body = {k: v for k, v in data.items()
            if k not in ("id", "created_at", "updated_at", "org_id", "created_by",
                         "engagement_id")}
    body = {**body, "id": fid, "engagement_id": engagement_id,
            "created_at": now, "updated_at": now}
    with _conn() as c:
        c.execute(
            """INSERT INTO findings
               (id, org_id, engagement_id, created_by, data, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (fid, org_id, engagement_id, created_by, _encode(body), now, now),
        )
    return body


def get_finding(fid: str, org_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT data FROM findings WHERE id=? AND org_id=? AND deleted_at IS NULL",
            (fid, org_id),
        ).fetchone()
    return _decode(row["data"]) if row else None


def update_finding(fid: str, org_id: str, data: dict) -> dict | None:
    existing = get_finding(fid, org_id)
    if not existing:
        return None
    now = _now()
    incoming = {k: v for k, v in data.items()
                if k not in ("id", "created_at", "org_id", "created_by")}
    merged = {**existing, **incoming, "id": fid,
              "created_at": existing.get("created_at", now), "updated_at": now}
    new_eid = merged.get("engagement_id")
    with _conn() as c:
        c.execute(
            "UPDATE findings SET data=?, engagement_id=?, updated_at=? WHERE id=? AND org_id=?",
            (_encode(merged), new_eid, now, fid, org_id),
        )
    return merged


def delete_finding(fid: str, org_id: str) -> bool:
    with _conn() as c:
        cur = c.execute(
            "UPDATE findings SET deleted_at=? WHERE id=? AND org_id=? AND deleted_at IS NULL",
            (_now(), fid, org_id),
        )
        return cur.rowcount > 0


def list_findings(org_id: str, engagement_id: str | None = None) -> list[dict]:
    with _conn() as c:
        if engagement_id is not None:
            rows = c.execute(
                "SELECT data FROM findings WHERE org_id=? AND engagement_id=? "
                "AND deleted_at IS NULL ORDER BY updated_at DESC",
                (org_id, engagement_id),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT data FROM findings WHERE org_id=? AND deleted_at IS NULL "
                "ORDER BY updated_at DESC",
                (org_id,),
            ).fetchall()
    return [_decode(r["data"]) for r in rows]


# ── Findings library (reusable writeup templates) ────────────────

def create_library_item(org_id: str, created_by: str, data: dict) -> dict:
    lid = _new_id()
    now = _now()
    body = {k: v for k, v in data.items()
            if k not in ("id", "created_at", "updated_at", "org_id", "created_by")}
    body = {**body, "id": lid, "created_at": now, "updated_at": now}
    with _conn() as c:
        c.execute(
            """INSERT INTO finding_library
               (id, org_id, created_by, data, created_at, updated_at)
               VALUES (?,?,?,?,?,?)""",
            (lid, org_id, created_by, _encode(body), now, now),
        )
    return body


def get_library_item(lid: str, org_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT data FROM finding_library WHERE id=? AND org_id=? AND deleted_at IS NULL",
            (lid, org_id),
        ).fetchone()
    return _decode(row["data"]) if row else None


def update_library_item(lid: str, org_id: str, data: dict) -> dict | None:
    existing = get_library_item(lid, org_id)
    if not existing:
        return None
    now = _now()
    incoming = {k: v for k, v in data.items()
                if k not in ("id", "created_at", "org_id", "created_by")}
    merged = {**existing, **incoming, "id": lid,
              "created_at": existing.get("created_at", now), "updated_at": now}
    with _conn() as c:
        c.execute(
            "UPDATE finding_library SET data=?, updated_at=? WHERE id=? AND org_id=?",
            (_encode(merged), now, lid, org_id),
        )
    return merged


def delete_library_item(lid: str, org_id: str) -> bool:
    with _conn() as c:
        cur = c.execute(
            "UPDATE finding_library SET deleted_at=? WHERE id=? AND org_id=? AND deleted_at IS NULL",
            (_now(), lid, org_id),
        )
        return cur.rowcount > 0


def list_library(org_id: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT data FROM finding_library WHERE org_id=? AND deleted_at IS NULL "
            "ORDER BY updated_at DESC",
            (org_id,),
        ).fetchall()
    return [_decode(r["data"]) for r in rows]


# ── Evidence (metadata; file bytes live in evidence_store) ───────

def _evidence_row(row: sqlite3.Row | None) -> dict | None:
    if not row:
        return None
    meta = json.loads(_ENC.decrypt(row["meta"]))
    return {
        "id": row["id"], "org_id": row["org_id"],
        "engagement_id": row["engagement_id"], "finding_id": row["finding_id"],
        "uploaded_by": row["uploaded_by"], "filename": meta.get("filename"),
        "content_type": row["content_type"], "size": row["size"],
        "sha256": row["sha256"], "created_at": row["created_at"],
    }


def create_evidence(org_id: str, uploaded_by: str, filename: str,
                    content_type: str | None, size: int, sha256: str,
                    engagement_id: str | None = None,
                    finding_id: str | None = None) -> dict:
    eid = _new_id()
    now = _now()
    meta = _ENC.encrypt(json.dumps({"filename": filename}))
    with _conn() as c:
        c.execute(
            """INSERT INTO evidence
               (id, org_id, engagement_id, finding_id, uploaded_by, meta,
                content_type, size, sha256, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (eid, org_id, engagement_id, finding_id, uploaded_by, meta,
             content_type, size, sha256, now),
        )
    return {
        "id": eid, "org_id": org_id, "engagement_id": engagement_id,
        "finding_id": finding_id, "uploaded_by": uploaded_by, "filename": filename,
        "content_type": content_type, "size": size, "sha256": sha256,
        "created_at": now,
    }


def get_evidence(eid: str, org_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM evidence WHERE id=? AND org_id=? AND deleted_at IS NULL",
            (eid, org_id),
        ).fetchone()
    return _evidence_row(row)


def list_evidence(org_id: str, engagement_id: str | None = None,
                  finding_id: str | None = None) -> list[dict]:
    q = "SELECT * FROM evidence WHERE org_id=? AND deleted_at IS NULL"
    params: list = [org_id]
    if engagement_id is not None:
        q += " AND engagement_id=?"; params.append(engagement_id)
    if finding_id is not None:
        q += " AND finding_id=?"; params.append(finding_id)
    q += " ORDER BY created_at DESC"
    with _conn() as c:
        rows = c.execute(q, params).fetchall()
    return [_evidence_row(r) for r in rows]


def delete_evidence(eid: str, org_id: str) -> bool:
    with _conn() as c:
        cur = c.execute(
            "UPDATE evidence SET deleted_at=? WHERE id=? AND org_id=? AND deleted_at IS NULL",
            (_now(), eid, org_id),
        )
        return cur.rowcount > 0


def purge_evidence(eid: str, org_id: str) -> bool:
    with _conn() as c:
        cur = c.execute("DELETE FROM evidence WHERE id=? AND org_id=?", (eid, org_id))
        return cur.rowcount > 0


# ── Engagement templates (reusable ROE presets) ─────────────────

def create_template(org_id: str, created_by: str, data: dict) -> dict:
    tid = _new_id()
    now = _now()
    body = {k: v for k, v in data.items()
            if k not in ("id", "created_at", "updated_at", "org_id", "created_by", "builtin")}
    body = {**body, "id": tid, "created_at": now, "updated_at": now}
    with _conn() as c:
        c.execute(
            """INSERT INTO engagement_templates
               (id, org_id, created_by, data, created_at, updated_at)
               VALUES (?,?,?,?,?,?)""",
            (tid, org_id, created_by, _encode(body), now, now),
        )
    return body


def get_template(tid: str, org_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT data FROM engagement_templates WHERE id=? AND org_id=? AND deleted_at IS NULL",
            (tid, org_id),
        ).fetchone()
    return _decode(row["data"]) if row else None


def update_template(tid: str, org_id: str, data: dict) -> dict | None:
    existing = get_template(tid, org_id)
    if not existing:
        return None
    now = _now()
    incoming = {k: v for k, v in data.items()
                if k not in ("id", "created_at", "org_id", "created_by", "builtin")}
    merged = {**existing, **incoming, "id": tid,
              "created_at": existing.get("created_at", now), "updated_at": now}
    with _conn() as c:
        c.execute(
            "UPDATE engagement_templates SET data=?, updated_at=? WHERE id=? AND org_id=?",
            (_encode(merged), now, tid, org_id),
        )
    return merged


def delete_template(tid: str, org_id: str) -> bool:
    with _conn() as c:
        cur = c.execute(
            "UPDATE engagement_templates SET deleted_at=? WHERE id=? AND org_id=? AND deleted_at IS NULL",
            (_now(), tid, org_id),
        )
        return cur.rowcount > 0


def list_templates(org_id: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT data FROM engagement_templates WHERE org_id=? AND deleted_at IS NULL "
            "ORDER BY updated_at DESC",
            (org_id,),
        ).fetchall()
    return [_decode(r["data"]) for r in rows]


# ── Shareable report links (client portal) ──────────────────────

def create_share(org_id: str, engagement_id: str, created_by: str,
                 ttl_days: int = 14, label: str | None = None) -> tuple[str, dict]:
    """Create a read-only share link. Returns (plaintext token, share dict).
    Only the token hash is stored."""
    sid = _new_id()
    token = new_token()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=ttl_days)
    with _conn() as c:
        c.execute(
            """INSERT INTO shares
               (id, token_hash, org_id, engagement_id, created_by, label, created_at, expires_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (sid, hash_token(token), org_id, engagement_id, created_by, label,
             now.isoformat(), expires.isoformat()),
        )
    return token, {"id": sid, "label": label, "created_at": now.isoformat(),
                   "expires_at": expires.isoformat(), "revoked": False}


def resolve_share(token: str) -> dict | None:
    """Return {id, org_id, engagement_id} for a valid, unexpired, un-revoked
    share, else None."""
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM shares WHERE token_hash=?", (hash_token(token),)
        ).fetchone()
    if not row or row["revoked"]:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    return {"id": row["id"], "org_id": row["org_id"],
            "engagement_id": row["engagement_id"]}


def list_shares(engagement_id: str, org_id: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT id, label, created_at, expires_at, revoked FROM shares "
            "WHERE engagement_id=? AND org_id=? ORDER BY created_at DESC",
            (engagement_id, org_id),
        ).fetchall()
    out = []
    now = datetime.now(timezone.utc)
    for r in rows:
        expired = datetime.fromisoformat(r["expires_at"]) < now
        out.append({"id": r["id"], "label": r["label"], "created_at": r["created_at"],
                    "expires_at": r["expires_at"], "revoked": bool(r["revoked"]),
                    "active": not r["revoked"] and not expired})
    return out


def revoke_share(share_id: str, org_id: str) -> bool:
    with _conn() as c:
        cur = c.execute(
            "UPDATE shares SET revoked=1 WHERE id=? AND org_id=?", (share_id, org_id)
        )
        return cur.rowcount > 0


# ── Audit log ────────────────────────────────────────────────────

def audit(action: str, *, actor_id: str | None = None, org_id: str | None = None,
          target_id: str | None = None, ip: str | None = None,
          detail: str | None = None) -> None:
    with _conn() as c:
        c.execute(
            """INSERT INTO audit_log (id, ts, actor_id, org_id, action, target_id, ip, detail)
               VALUES (?,?,?,?,?,?,?,?)""",
            (_new_id(), _now(), actor_id, org_id, action, target_id, ip, detail),
        )


def list_audit(org_id: str, limit: int = 200) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT ts, actor_id, action, target_id, ip, detail FROM audit_log "
            "WHERE org_id=? ORDER BY ts DESC LIMIT ?",
            (org_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]
