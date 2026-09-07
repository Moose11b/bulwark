"""
Siege Tower — standalone FastAPI application.

Wraps the dependency-free planning engine in a small, hardened web service and
serves the planner UI. It exposes ONLY planning and documentation operations —
nothing here executes a command, launches a tool, or connects to a target, and
nothing reads or moves data from a client's systems.

Security posture (see server/security.py, server/db.py, server/auth.py):
  * bearer-token authentication on every /api route except health and login;
  * per-organization tenancy — a caller only ever sees its own org's data;
  * role-based authorization (admin / operator / viewer);
  * validated, size-limited request bodies (no mass assignment);
  * rate limiting, security headers + strict CSP, and audit logging;
  * engagement data encrypted at rest when a key is configured.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import dataclasses

from siege_tower import (
    BoxType, EngagementInput, Objective, build_plans, suggest_followups,
)
from siege_tower.playbook import DEFAULT_PLAYBOOK
from siege_tower.render import plan_result_to_dict
from siege_tower.schema import Platform, Restriction, Tactic

_PLAYS_BY_ID = {p.technique_id: p for p in DEFAULT_PLAYBOOK}

from . import auth, db
from .bootstrap import build_bootstrap
from .report import build_report, render_markdown
from .security import (
    MIN_PASSWORD_LENGTH,
    BodySizeLimitMiddleware,
    RateLimiter,
    SecurityHeadersMiddleware,
    verify_password,
)

log = logging.getLogger("siege.app")

_MAX_BODY_BYTES = int(os.environ.get("SIEGE_MAX_BODY_BYTES", str(1_048_576)))
_BEHIND_TLS = os.environ.get("SIEGE_BEHIND_TLS") == "1" or bool(
    os.environ.get("SIEGE_TLS_CERT")
)

_login_limiter = RateLimiter(limit=10, window_seconds=300)      # 10 / 5 min / ip+user
_api_limiter = RateLimiter(limit=600, window_seconds=60)        # 600 / min / ip

_RESOLVED_WORKED = {"succeeded", "fell_back", "failed", "blocked"}


@asynccontextmanager
async def _lifespan(app: "FastAPI"):
    db.init_db()
    db.purge_expired_sessions()
    _ensure_bootstrap_admin()
    _bootstrap()  # warm the cache
    yield


app = FastAPI(title="Siege Tower", version="0.2.0", lifespan=_lifespan)
app.add_middleware(SecurityHeadersMiddleware, hsts=_BEHIND_TLS)
app.add_middleware(BodySizeLimitMiddleware, max_bytes=_MAX_BODY_BYTES)


@app.middleware("http")
async def _rate_limit(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.url.path != "/api/health":
        ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() \
            if os.environ.get("SIEGE_TRUST_PROXY") == "1" else \
            (request.client.host if request.client else "unknown")
        if not _api_limiter.check(ip):
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
    return await call_next(request)


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    # Never leak internal detail to the client; log it server-side.
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


_WEB_DIR = Path(__file__).resolve().parent.parent / "web"


@lru_cache(maxsize=1)
def _bootstrap() -> dict:
    return build_bootstrap()


@lru_cache(maxsize=1)
def _pb_map() -> dict:
    return {p["technique_id"]: p for p in _bootstrap()["playbook"]}


def _ensure_bootstrap_admin() -> None:
    """On an empty install, create the first org + admin so the app is usable
    but never open. Password comes from SIEGE_ADMIN_PASSWORD, or is generated
    and printed once."""
    if db.count_users() > 0:
        return
    org = db.create_org(os.environ.get("SIEGE_ORG_NAME", "Default"))
    username = os.environ.get("SIEGE_ADMIN_USERNAME", "admin")
    password = os.environ.get("SIEGE_ADMIN_PASSWORD")
    generated = False
    if not password:
        import secrets
        password = secrets.token_urlsafe(18)
        generated = True
    db.create_user(org["id"], username, password, role="admin")
    if generated:
        banner = "=" * 72
        print(
            f"\n{banner}\nSIEGE TOWER — first-run admin created\n"
            f"  username: {username}\n  password: {password}\n"
            f"  (set SIEGE_ADMIN_PASSWORD to choose your own; change it after login)\n"
            f"{banner}",
            flush=True,
        )


# ── Request models ───────────────────────────────────────────────

_STR = Field(default=None, max_length=255)
_LONG = Field(default=None, max_length=20000)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=1, max_length=1024)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=1024)


class UserCreateIn(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=1024)
    role: str = "operator"
    email: str | None = Field(default=None, max_length=320)


class UserUpdateIn(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=MIN_PASSWORD_LENGTH, max_length=1024)


class PlanStep(BaseModel):
    uid: str = Field(max_length=64)
    tid: str = Field(max_length=32)


class LogEntry(BaseModel):
    model_config = {"extra": "ignore"}
    outcome: str | None = Field(default=None, max_length=32)
    operator: str | None = Field(default=None, max_length=255)
    notes: str | None = _LONG
    evidence: list[str] = Field(default_factory=list, max_length=200)
    targets: list[str] = Field(default_factory=list, max_length=200)
    startedAt: str | None = Field(default=None, max_length=64)
    completedAt: str | None = Field(default=None, max_length=64)


class RoeIn(BaseModel):
    objective: str = Field(max_length=64)
    box_type: str = Field(default="black", max_length=16)
    scope_platforms: list[str] = Field(default_factory=list, max_length=32)
    provided_access: list[str] = Field(default_factory=list, max_length=32)
    restrictions: list[str] = Field(default_factory=list, max_length=32)
    forbidden_technique_ids: list[str] = Field(default_factory=list, max_length=200)
    forbidden_tactics: list[str] = Field(default_factory=list, max_length=32)
    time_budget_hours: float | None = Field(default=None, ge=0, le=100000)
    allow_evidence_removal: bool = False
    emulate_adversary: str | None = Field(default=None, max_length=64)
    objective_note: str | None = _LONG
    max_plans: int = Field(default=5, ge=1, le=10)


class FollowupIn(BaseModel):
    failed_technique_id: str = Field(min_length=1, max_length=32)
    objective: str = Field(max_length=64)
    box_type: str = Field(default="black", max_length=16)
    scope_platforms: list[str] = Field(default_factory=list, max_length=32)
    provided_access: list[str] = Field(default_factory=list, max_length=32)
    restrictions: list[str] = Field(default_factory=list, max_length=32)
    forbidden_technique_ids: list[str] = Field(default_factory=list, max_length=200)
    forbidden_tactics: list[str] = Field(default_factory=list, max_length=32)
    allow_evidence_removal: bool = False
    # Technique IDs the team has already completed (succeeded/fell back), used to
    # decide which follow-ups are ready now and still reach the objective.
    succeeded_technique_ids: list[str] = Field(default_factory=list, max_length=1000)


class EngagementIn(BaseModel):
    model_config = {"extra": "ignore"}
    name: str = Field(min_length=1, max_length=255)
    client: str | None = _STR
    authorization_ref: str | None = _STR
    objective: str = Field(default="", max_length=64)
    box_type: str = Field(default="black", max_length=16)
    scope_platforms: list[str] = Field(default_factory=list, max_length=32)
    restrictions: list[str] = Field(default_factory=list, max_length=32)
    in_scope_targets: list[str] = Field(default_factory=list, max_length=512)
    time_budget_hours: float | None = Field(default=None, ge=0, le=100000)
    plan: list[PlanStep] = Field(default_factory=list, max_length=1000)
    logs: dict[str, LogEntry] = Field(default_factory=dict)
    status: str | None = Field(default=None, max_length=32)


class EngagementUpdateIn(BaseModel):
    """A PUT may carry a full engagement (from the UI) or a partial patch; only
    the fields actually supplied are merged over the stored record."""
    model_config = {"extra": "ignore"}
    name: str | None = Field(default=None, min_length=1, max_length=255)
    client: str | None = _STR
    authorization_ref: str | None = _STR
    objective: str | None = Field(default=None, max_length=64)
    box_type: str | None = Field(default=None, max_length=16)
    scope_platforms: list[str] | None = Field(default=None, max_length=32)
    restrictions: list[str] | None = Field(default=None, max_length=32)
    in_scope_targets: list[str] | None = Field(default=None, max_length=512)
    time_budget_hours: float | None = Field(default=None, ge=0, le=100000)
    plan: list[PlanStep] | None = Field(default=None, max_length=1000)
    logs: dict[str, LogEntry] | None = None
    status: str | None = Field(default=None, max_length=32)


# ── Health & auth ────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "siege-tower"}


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request):
    ip = request.client.host if request.client else "unknown"
    if not _login_limiter.check(f"{ip}:{body.username}"):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")
    user = db.get_user_by_username(body.username)
    ok = bool(user) and user["is_active"] and verify_password(body.password, user["password_hash"])
    if not ok:
        db.audit("login_failed", org_id=(user or {}).get("org_id"),
                 target_id=(user or {}).get("id"), ip=ip, detail=body.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = db.create_session(user["id"])
    db.mark_login(user["id"])
    db.audit("login", actor_id=user["id"], org_id=user["org_id"], ip=ip)
    return {"token": token, "user": _public_user(user)}


@app.post("/api/auth/logout")
def logout(request: Request, user: dict = Depends(auth.current_user)):
    # Revoke the presenting token.
    hdr = request.headers.get("authorization", "")
    if hdr.lower().startswith("bearer "):
        db.revoke_session(hdr[7:].strip())
    db.audit("logout", actor_id=user["id"], org_id=user["org_id"],
             ip=getattr(request.state, "client_ip", None))
    return {"status": "ok"}


@app.get("/api/auth/me")
def me(user: dict = Depends(auth.current_user)):
    return _public_user(user)


@app.post("/api/auth/change-password")
def change_password(body: ChangePasswordIn, request: Request,
                    user: dict = Depends(auth.current_user)):
    full = db.get_user(user["id"])
    if not full or not verify_password(body.current_password, full["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    db.set_password(user["id"], body.new_password)
    db.audit("password_change", actor_id=user["id"], org_id=user["org_id"],
             ip=getattr(request.state, "client_ip", None))
    return {"status": "ok"}


def _public_user(u: dict) -> dict:
    return {"id": u["id"], "username": u["username"], "email": u.get("email"),
            "role": u["role"], "org_id": u["org_id"]}


# ── User management (admin) ──────────────────────────────────────

@app.get("/api/users")
def list_users(user: dict = Depends(auth.require_role("admin"))):
    return {"users": [_public_user(u) for u in db.list_users(user["org_id"])]}


@app.post("/api/users", status_code=201)
def create_user(body: UserCreateIn, request: Request,
                user: dict = Depends(auth.require_role("admin"))):
    if body.role not in db.VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    if db.get_user_by_username(body.username):
        raise HTTPException(status_code=409, detail="Username already exists")
    try:
        created = db.create_user(user["org_id"], body.username, body.password,
                                 role=body.role, email=body.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    db.audit("user_create", actor_id=user["id"], org_id=user["org_id"],
             target_id=created["id"], ip=getattr(request.state, "client_ip", None))
    return _public_user(created)


@app.patch("/api/users/{uid}")
def update_user(uid: str, body: UserUpdateIn, request: Request,
                user: dict = Depends(auth.require_role("admin"))):
    if uid == user["id"] and body.is_active is False:
        raise HTTPException(status_code=400, detail="You cannot deactivate yourself")
    try:
        updated = db.update_user(uid, user["org_id"], role=body.role,
                                 is_active=body.is_active, password=body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    db.audit("user_update", actor_id=user["id"], org_id=user["org_id"],
             target_id=uid, ip=getattr(request.state, "client_ip", None))
    return _public_user(updated)


@app.get("/api/audit")
def audit_log(user: dict = Depends(auth.require_role("admin"))):
    return {"entries": db.list_audit(user["org_id"])}


# ── Planning (auth required) ─────────────────────────────────────

@app.get("/api/bootstrap")
def bootstrap(user: dict = Depends(auth.current_user)):
    return _bootstrap()


def _coerce_list(values, enum_cls):
    out = []
    for v in values or []:
        try:
            out.append(enum_cls(v))
        except ValueError:
            pass
    return out


@app.post("/api/plan")
def plan(roe: RoeIn, user: dict = Depends(auth.current_user)):
    """Rank plans for a Rules-of-Engagement payload (a pure computation)."""
    try:
        objective = Objective(roe.objective)
        box_type = BoxType(roe.box_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid ROE: {exc}")
    inp = EngagementInput(
        objective=objective, box_type=box_type,
        scope_platforms=_coerce_list(roe.scope_platforms, Platform),
        provided_access=list(roe.provided_access),
        restrictions=_coerce_list(roe.restrictions, Restriction),
        forbidden_technique_ids=list(roe.forbidden_technique_ids),
        forbidden_tactics=_coerce_list(roe.forbidden_tactics, Tactic),
        time_budget_hours=roe.time_budget_hours,
        allow_evidence_removal=roe.allow_evidence_removal,
        emulate_adversary=roe.emulate_adversary,
        objective_note=roe.objective_note,
    )
    return plan_result_to_dict(build_plans(inp))


@app.post("/api/followups")
def followups(body: FollowupIn, user: dict = Depends(auth.current_user)):
    """Given a step that failed, suggest ranked alternative techniques that
    reach the same goal and keep a path to the objective open.

    A pure computation over the playbook and the ROE — nothing is contacted."""
    try:
        objective = Objective(body.objective)
        box_type = BoxType(body.box_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid ROE: {exc}")
    inp = EngagementInput(
        objective=objective, box_type=box_type,
        scope_platforms=_coerce_list(body.scope_platforms, Platform),
        provided_access=list(body.provided_access),
        restrictions=_coerce_list(body.restrictions, Restriction),
        forbidden_technique_ids=list(body.forbidden_technique_ids),
        forbidden_tactics=_coerce_list(body.forbidden_tactics, Tactic),
        allow_evidence_removal=body.allow_evidence_removal,
    )
    achieved: set[str] = set()
    for tid in body.succeeded_technique_ids:
        p = _PLAYS_BY_ID.get(tid)
        if p:
            achieved.update(p.provides)
    suggestions = suggest_followups(body.failed_technique_id, inp, achieved=achieved)
    return {
        "failed_technique_id": body.failed_technique_id,
        "suggestions": [dataclasses.asdict(s) for s in suggestions],
    }


# ── Engagements (auth + tenancy + roles) ─────────────────────────

def _progress(eng: dict) -> dict:
    plan = eng.get("plan", [])
    logs = eng.get("logs", {})
    worked = sum(1 for s in plan
                 if (logs.get(s.get("uid"), {}) or {}).get("outcome") in _RESOLVED_WORKED)
    total = len(plan)
    return {"steps": total, "worked": worked,
            "pct": round(100.0 * worked / total) if total else 0}


@app.get("/api/engagements")
def list_engagements(user: dict = Depends(auth.current_user)):
    out = []
    for e in db.list_engagements(user["org_id"]):
        out.append({
            "id": e.get("id"), "name": e.get("name"), "client": e.get("client"),
            "objective": e.get("objective"), "box_type": e.get("box_type"),
            "status": e.get("status"), "updated_at": e.get("updated_at"),
            "progress": _progress(e),
        })
    return {"engagements": out}


@app.post("/api/engagements", status_code=201)
def create_engagement(body: EngagementIn, request: Request,
                      user: dict = Depends(auth.require_role("operator"))):
    eng = db.create_engagement(user["org_id"], user["id"], body.model_dump())
    db.audit("engagement_create", actor_id=user["id"], org_id=user["org_id"],
             target_id=eng["id"], ip=getattr(request.state, "client_ip", None))
    return eng


@app.get("/api/engagements/{eid}")
def get_engagement(eid: str, user: dict = Depends(auth.current_user)):
    e = db.get_engagement(eid, user["org_id"])
    if not e:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return e


@app.put("/api/engagements/{eid}")
def update_engagement(eid: str, body: EngagementUpdateIn, request: Request,
                      user: dict = Depends(auth.require_role("operator"))):
    e = db.update_engagement(eid, user["org_id"], body.model_dump(exclude_unset=True))
    if not e:
        raise HTTPException(status_code=404, detail="Engagement not found")
    db.audit("engagement_update", actor_id=user["id"], org_id=user["org_id"],
             target_id=eid, ip=getattr(request.state, "client_ip", None))
    return e


@app.delete("/api/engagements/{eid}", status_code=204)
def delete_engagement(eid: str, request: Request,
                      user: dict = Depends(auth.require_role("operator"))):
    if not db.delete_engagement(eid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Engagement not found")
    db.audit("engagement_delete", actor_id=user["id"], org_id=user["org_id"],
             target_id=eid, ip=getattr(request.state, "client_ip", None))
    return Response(status_code=204)


@app.delete("/api/engagements/{eid}/purge", status_code=204)
def purge_engagement(eid: str, request: Request,
                     user: dict = Depends(auth.require_role("admin"))):
    """Hard delete (admin only) — irreversible, for right-to-erasure requests."""
    if not db.purge_engagement(eid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Engagement not found")
    db.audit("engagement_purge", actor_id=user["id"], org_id=user["org_id"],
             target_id=eid, ip=getattr(request.state, "client_ip", None))
    return Response(status_code=204)


@app.get("/api/engagements/{eid}/report")
def engagement_report(eid: str, format: str = "json",
                      user: dict = Depends(auth.current_user)):
    e = db.get_engagement(eid, user["org_id"])
    if not e:
        raise HTTPException(status_code=404, detail="Engagement not found")
    rep = build_report(e, _pb_map())
    if format == "markdown":
        return Response(content=render_markdown(rep), media_type="text/markdown")
    return rep


# Serve the web UI last, so it never shadows the /api routes above.
if _WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_WEB_DIR), html=True), name="web")
