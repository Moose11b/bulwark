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
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from fastapi import (
    Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile,
)
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import evidence_store

import dataclasses

from siege_tower import (
    BoxType, EngagementInput, Objective, build_plans, suggest_followups,
)
from siege_tower.cvss import score_vector
from siege_tower.playbook import DEFAULT_PLAYBOOK
from siege_tower.render import plan_result_to_dict
from siege_tower.schema import Platform, Restriction, Tactic

_PLAYS_BY_ID = {p.technique_id: p for p in DEFAULT_PLAYBOOK}

FINDING_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
FINDING_STATUSES = {"open", "in_remediation", "retest", "fixed",
                    "risk_accepted", "false_positive"}


def _finalize_finding(data: dict) -> dict:
    """Auto-derive CVSS score/severity from a v3.x vector when present and not
    explicitly overridden. Keeps scoring consistent and saves manual effort."""
    vector = data.get("cvss_vector")
    if vector:
        scored = score_vector(vector)
        if scored["score"] is not None:
            if data.get("cvss_score") is None:
                data["cvss_score"] = scored["score"]
            if not data.get("severity"):
                data["severity"] = scored["severity"]
            if not data.get("cvss_version"):
                data["cvss_version"] = scored["version"]
    return data

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
app.add_middleware(
    BodySizeLimitMiddleware, max_bytes=_MAX_BODY_BYTES,
    upload_prefixes=("/api/evidence", "/api/imports"),
    upload_max_bytes=evidence_store.MAX_EVIDENCE_BYTES + 1_048_576,  # + multipart overhead
)


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


class FindingIn(BaseModel):
    model_config = {"extra": "ignore"}
    title: str = Field(min_length=1, max_length=300)
    engagement_id: str | None = Field(default=None, max_length=64)
    severity: str | None = Field(default=None, max_length=20)
    cvss_vector: str | None = Field(default=None, max_length=120)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    status: str = Field(default="open", max_length=20)
    affected_assets: list[str] = Field(default_factory=list, max_length=1000)
    description: str | None = _LONG
    impact: str | None = _LONG
    reproduction: str | None = _LONG
    remediation: str | None = _LONG
    references: list[str] = Field(default_factory=list, max_length=200)
    technique_ids: list[str] = Field(default_factory=list, max_length=200)
    cwe: str | None = Field(default=None, max_length=32)
    tags: list[str] = Field(default_factory=list, max_length=100)
    evidence_ids: list[str] = Field(default_factory=list, max_length=500)
    library_id: str | None = Field(default=None, max_length=64)


class FindingUpdateIn(BaseModel):
    model_config = {"extra": "ignore"}
    title: str | None = Field(default=None, min_length=1, max_length=300)
    engagement_id: str | None = Field(default=None, max_length=64)
    severity: str | None = Field(default=None, max_length=20)
    cvss_vector: str | None = Field(default=None, max_length=120)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    status: str | None = Field(default=None, max_length=20)
    affected_assets: list[str] | None = Field(default=None, max_length=1000)
    description: str | None = _LONG
    impact: str | None = _LONG
    reproduction: str | None = _LONG
    remediation: str | None = _LONG
    references: list[str] | None = Field(default=None, max_length=200)
    technique_ids: list[str] | None = Field(default=None, max_length=200)
    cwe: str | None = Field(default=None, max_length=32)
    tags: list[str] | None = Field(default=None, max_length=100)
    evidence_ids: list[str] | None = Field(default=None, max_length=500)


class RetestIn(BaseModel):
    status: str = Field(max_length=20)
    note: str | None = _LONG


class ShareCreateIn(BaseModel):
    ttl_days: int = Field(default=14, ge=1, le=365)
    label: str | None = Field(default=None, max_length=120)


class LibraryItemIn(BaseModel):
    """A reusable finding template — no engagement/asset/evidence specifics."""
    model_config = {"extra": "ignore"}
    title: str = Field(min_length=1, max_length=300)
    severity: str | None = Field(default=None, max_length=20)
    cvss_vector: str | None = Field(default=None, max_length=120)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    description: str | None = _LONG
    impact: str | None = _LONG
    remediation: str | None = _LONG
    references: list[str] = Field(default_factory=list, max_length=200)
    technique_ids: list[str] = Field(default_factory=list, max_length=200)
    cwe: str | None = Field(default=None, max_length=32)
    tags: list[str] = Field(default_factory=list, max_length=100)


class LibraryItemUpdateIn(BaseModel):
    model_config = {"extra": "ignore"}
    title: str | None = Field(default=None, min_length=1, max_length=300)
    severity: str | None = Field(default=None, max_length=20)
    cvss_vector: str | None = Field(default=None, max_length=120)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    description: str | None = _LONG
    impact: str | None = _LONG
    remediation: str | None = _LONG
    references: list[str] | None = Field(default=None, max_length=200)
    technique_ids: list[str] | None = Field(default=None, max_length=200)
    cwe: str | None = Field(default=None, max_length=32)
    tags: list[str] | None = Field(default=None, max_length=100)


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


def _assemble_report(eid: str, org_id: str) -> dict:
    e = db.get_engagement(eid, org_id)
    if not e:
        raise HTTPException(status_code=404, detail="Engagement not found")
    rep = build_report(e, _pb_map())
    # Attach findings (with resolved evidence metadata) and org branding.
    findings = db.list_findings(org_id, engagement_id=eid)
    for f in findings:
        ev = []
        for evid in (f.get("evidence_ids") or []):
            meta = db.get_evidence(evid, org_id)
            if meta:
                ev.append({"filename": meta["filename"], "sha256": meta["sha256"],
                           "size": meta["size"]})
        f["evidence"] = ev
    rep["findings"] = findings
    org = db.get_org(org_id)
    rep["org_name"] = org["name"] if org else None
    return rep


@app.get("/api/engagements/{eid}/report")
def engagement_report(eid: str, format: str = "json",
                      user: dict = Depends(auth.current_user)):
    rep = _assemble_report(eid, user["org_id"])
    name = (rep["engagement"].get("name") or "engagement").replace('"', "").replace("\n", "")

    if format == "markdown":
        return Response(content=render_markdown(rep), media_type="text/markdown")
    if format == "docx":
        from . import report_export
        data = report_export.to_docx(rep)
        return Response(
            content=data,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="{name}.docx"'},
        )
    if format == "pdf":
        from . import report_export
        data = report_export.to_pdf(rep)
        return Response(content=data, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{name}.pdf"'})
    if format != "json":
        raise HTTPException(status_code=400, detail="Unsupported format")
    return rep


@app.get("/api/engagements/{eid}/navigator")
def navigator_layer(eid: str, user: dict = Depends(auth.current_user)):
    """Export the engagement as a MITRE ATT&CK Navigator layer (JSON)."""
    from . import navigator
    e = db.get_engagement(eid, user["org_id"])
    if not e:
        raise HTTPException(status_code=404, detail="Engagement not found")
    findings = db.list_findings(user["org_id"], engagement_id=eid)
    layer = navigator.build_layer(e, _PLAYS_BY_ID, findings)
    import json as _json
    name = (e.get("name") or "engagement").replace('"', "").replace("\n", "")
    return Response(
        content=_json.dumps(layer, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}.navigator.json"'},
    )


# ── Shareable report links (client portal) ───────────────────────

@app.post("/api/engagements/{eid}/shares", status_code=201)
def create_share(eid: str, body: ShareCreateIn, request: Request,
                 user: dict = Depends(auth.require_role("operator"))):
    if not db.get_engagement(eid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Engagement not found")
    token, share = db.create_share(user["org_id"], eid, user["id"],
                                   body.ttl_days, body.label)
    db.audit("share_create", actor_id=user["id"], org_id=user["org_id"],
             target_id=eid, ip=getattr(request.state, "client_ip", None))
    return {"token": token, "url": f"/share.html#{token}", **share}


@app.get("/api/engagements/{eid}/shares")
def list_shares(eid: str, user: dict = Depends(auth.current_user)):
    if not db.get_engagement(eid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {"shares": db.list_shares(eid, user["org_id"])}


@app.delete("/api/shares/{sid}", status_code=204)
def revoke_share(sid: str, request: Request,
                 user: dict = Depends(auth.require_role("operator"))):
    if not db.revoke_share(sid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Share not found")
    db.audit("share_revoke", actor_id=user["id"], org_id=user["org_id"],
             target_id=sid, ip=getattr(request.state, "client_ip", None))
    return Response(status_code=204)


# Public, unauthenticated — a client opens the shared read-only report.
@app.get("/api/share/{token}")
def public_share(token: str):
    s = db.resolve_share(token)
    if not s:
        raise HTTPException(status_code=404, detail="This link is invalid or has expired")
    rep = _assemble_report(s["engagement_id"], s["org_id"])
    rep["shared"] = True
    return rep


@app.get("/api/share/{token}/download")
def public_share_download(token: str, format: str = "pdf"):
    s = db.resolve_share(token)
    if not s:
        raise HTTPException(status_code=404, detail="This link is invalid or has expired")
    rep = _assemble_report(s["engagement_id"], s["org_id"])
    name = (rep["engagement"].get("name") or "engagement").replace('"', "").replace("\n", "")
    if format == "markdown":
        return Response(content=render_markdown(rep), media_type="text/markdown")
    if format == "docx":
        from . import report_export
        return Response(
            content=report_export.to_docx(rep),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="{name}.docx"'})
    if format == "pdf":
        from . import report_export
        return Response(content=report_export.to_pdf(rep), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{name}.pdf"'})
    raise HTTPException(status_code=400, detail="Unsupported format")


_OPEN_STATUSES = {"open", "in_remediation", "retest"}
_RESOLVED_STATUSES = {"fixed", "risk_accepted", "false_positive"}


@app.get("/api/engagements/{eid}/remediation")
def remediation_summary(eid: str, user: dict = Depends(auth.current_user)):
    """Remediation/retest posture for an engagement: counts by status and
    severity, and the findings still needing a retest."""
    if not db.get_engagement(eid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Engagement not found")
    findings = db.list_findings(user["org_id"], engagement_id=eid)
    by_status: dict[str, int] = {}
    open_by_severity: dict[str, int] = {}
    needing_retest = []
    for f in findings:
        st = f.get("status") or "open"
        by_status[st] = by_status.get(st, 0) + 1
        if st in _OPEN_STATUSES:
            sev = f.get("severity") or "informational"
            open_by_severity[sev] = open_by_severity.get(sev, 0) + 1
            needing_retest.append({
                "id": f.get("id"), "title": f.get("title"),
                "severity": f.get("severity"), "status": st,
                "cvss_score": f.get("cvss_score"),
            })
    total = len(findings)
    resolved = sum(v for k, v in by_status.items() if k in _RESOLVED_STATUSES)
    return {
        "engagement_id": eid,
        "total_findings": total,
        "resolved": resolved,
        "open": total - resolved,
        "remediation_pct": round(100.0 * resolved / total, 1) if total else 0.0,
        "by_status": by_status,
        "open_by_severity": open_by_severity,
        "needing_retest": needing_retest,
    }


# ── CVSS helper ──────────────────────────────────────────────────

@app.get("/api/cvss")
def cvss(vector: str, user: dict = Depends(auth.current_user)):
    """Score a CVSS vector (v3.x computed; v4.0 recognized, score manual)."""
    return score_vector(vector)


# ── Findings (auth + tenancy + roles) ────────────────────────────

def _validate_finding_enums(severity: str | None, status: str | None) -> None:
    if severity and severity not in FINDING_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
    if status and status not in FINDING_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")


@app.get("/api/findings")
def list_findings(engagement_id: str | None = None,
                  user: dict = Depends(auth.current_user)):
    return {"findings": db.list_findings(user["org_id"], engagement_id)}


@app.post("/api/findings", status_code=201)
def create_finding(body: FindingIn, request: Request,
                   user: dict = Depends(auth.require_role("operator"))):
    _validate_finding_enums(body.severity, body.status)
    data = _finalize_finding(body.model_dump())
    eid = data.pop("engagement_id", None)
    if eid and not db.get_engagement(eid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Engagement not found")
    f = db.create_finding(user["org_id"], user["id"], eid, data)
    db.audit("finding_create", actor_id=user["id"], org_id=user["org_id"],
             target_id=f["id"], ip=getattr(request.state, "client_ip", None))
    return f


@app.get("/api/findings/{fid}")
def get_finding(fid: str, user: dict = Depends(auth.current_user)):
    f = db.get_finding(fid, user["org_id"])
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f


def _history_entry(status: str, user: dict, note: str | None) -> dict:
    return {"status": status, "at": datetime.now(timezone.utc).isoformat(),
            "by": user.get("username"), "note": note}


@app.put("/api/findings/{fid}")
def update_finding(fid: str, body: FindingUpdateIn, request: Request,
                   user: dict = Depends(auth.require_role("operator"))):
    _validate_finding_enums(body.severity, body.status)
    existing = db.get_finding(fid, user["org_id"])
    if not existing:
        raise HTTPException(status_code=404, detail="Finding not found")
    data = _finalize_finding(body.model_dump(exclude_unset=True))
    if "engagement_id" in data and data["engagement_id"] \
            and not db.get_engagement(data["engagement_id"], user["org_id"]):
        raise HTTPException(status_code=404, detail="Engagement not found")
    # Record a status transition in the finding's history (remediation trail).
    if "status" in data and data["status"] != existing.get("status"):
        history = list(existing.get("status_history") or [])
        history.append(_history_entry(data["status"], user, None))
        data["status_history"] = history
    f = db.update_finding(fid, user["org_id"], data)
    db.audit("finding_update", actor_id=user["id"], org_id=user["org_id"],
             target_id=fid, ip=getattr(request.state, "client_ip", None))
    return f


@app.post("/api/findings/{fid}/retest")
def retest_finding(fid: str, body: RetestIn, request: Request,
                   user: dict = Depends(auth.require_role("operator"))):
    """Record a retest outcome: set the finding's status and append a dated,
    attributed entry (with an optional note) to its remediation history."""
    _validate_finding_enums(None, body.status)
    existing = db.get_finding(fid, user["org_id"])
    if not existing:
        raise HTTPException(status_code=404, detail="Finding not found")
    history = list(existing.get("status_history") or [])
    history.append(_history_entry(body.status, user, body.note))
    f = db.update_finding(fid, user["org_id"],
                          {"status": body.status, "status_history": history})
    db.audit("finding_retest", actor_id=user["id"], org_id=user["org_id"],
             target_id=fid, ip=getattr(request.state, "client_ip", None),
             detail=body.status)
    return f


@app.get("/api/findings/{fid}/history")
def finding_history(fid: str, user: dict = Depends(auth.current_user)):
    f = db.get_finding(fid, user["org_id"])
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"status": f.get("status"), "history": f.get("status_history") or []}


@app.delete("/api/findings/{fid}", status_code=204)
def delete_finding(fid: str, request: Request,
                   user: dict = Depends(auth.require_role("operator"))):
    if not db.delete_finding(fid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Finding not found")
    db.audit("finding_delete", actor_id=user["id"], org_id=user["org_id"],
             target_id=fid, ip=getattr(request.state, "client_ip", None))
    return Response(status_code=204)


_LIBRARY_FIELDS = ("title", "severity", "cvss_vector", "cvss_score", "description",
                   "impact", "remediation", "references", "technique_ids", "cwe", "tags")


@app.post("/api/findings/{fid}/save-to-library", status_code=201)
def save_finding_to_library(fid: str, request: Request,
                            user: dict = Depends(auth.require_role("operator"))):
    """Create a reusable library template from an existing finding."""
    f = db.get_finding(fid, user["org_id"])
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    tmpl = {k: f.get(k) for k in _LIBRARY_FIELDS if f.get(k) is not None}
    item = db.create_library_item(user["org_id"], user["id"], tmpl)
    db.audit("library_create_from_finding", actor_id=user["id"], org_id=user["org_id"],
             target_id=item["id"], ip=getattr(request.state, "client_ip", None))
    return item


# ── Scan import (Bulwark / SARIF → findings) ─────────────────────

@app.post("/api/imports", status_code=201)
async def import_scan(
    request: Request,
    file: UploadFile = File(...),
    engagement_id: str = Form(...),
    user: dict = Depends(auth.require_role("operator")),
):
    """Import a Bulwark scan result (native JSON) or a SARIF file as findings
    under an engagement. A pure parse of the uploaded file — nothing is run."""
    from . import importers
    cap = evidence_store.MAX_EVIDENCE_BYTES
    contents = await file.read(cap + 1)
    if len(contents) > cap:
        raise HTTPException(status_code=413, detail="Import file too large")
    if not contents:
        raise HTTPException(status_code=400, detail="Empty file")
    if not db.get_engagement(engagement_id, user["org_id"]):
        raise HTTPException(status_code=404, detail="Engagement not found")
    import json as _json
    try:
        data = _json.loads(contents)
    except ValueError:
        raise HTTPException(status_code=400, detail="File is not valid JSON")
    try:
        source, parsed = importers.parse(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    created = []
    for fd in parsed:
        f = db.create_finding(user["org_id"], user["id"], engagement_id,
                              _finalize_finding(dict(fd)))
        created.append({"id": f["id"], "title": f["title"], "severity": f.get("severity")})
    db.audit("scan_import", actor_id=user["id"], org_id=user["org_id"],
             target_id=engagement_id, ip=getattr(request.state, "client_ip", None),
             detail=f"{source}: {len(created)} finding(s)")
    return {"source": source, "imported": len(created), "findings": created}


# ── Findings library ─────────────────────────────────────────────

@app.get("/api/library")
def list_library(user: dict = Depends(auth.current_user)):
    return {"library": db.list_library(user["org_id"])}


@app.post("/api/library", status_code=201)
def create_library_item(body: LibraryItemIn, request: Request,
                        user: dict = Depends(auth.require_role("operator"))):
    _validate_finding_enums(body.severity, None)
    item = db.create_library_item(user["org_id"], user["id"],
                                  _finalize_finding(body.model_dump()))
    db.audit("library_create", actor_id=user["id"], org_id=user["org_id"],
             target_id=item["id"], ip=getattr(request.state, "client_ip", None))
    return item


@app.get("/api/library/{lid}")
def get_library_item(lid: str, user: dict = Depends(auth.current_user)):
    item = db.get_library_item(lid, user["org_id"])
    if not item:
        raise HTTPException(status_code=404, detail="Library item not found")
    return item


@app.put("/api/library/{lid}")
def update_library_item(lid: str, body: LibraryItemUpdateIn, request: Request,
                        user: dict = Depends(auth.require_role("operator"))):
    _validate_finding_enums(body.severity, None)
    item = db.update_library_item(lid, user["org_id"],
                                  _finalize_finding(body.model_dump(exclude_unset=True)))
    if not item:
        raise HTTPException(status_code=404, detail="Library item not found")
    db.audit("library_update", actor_id=user["id"], org_id=user["org_id"],
             target_id=lid, ip=getattr(request.state, "client_ip", None))
    return item


@app.delete("/api/library/{lid}", status_code=204)
def delete_library_item(lid: str, request: Request,
                        user: dict = Depends(auth.require_role("operator"))):
    if not db.delete_library_item(lid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Library item not found")
    db.audit("library_delete", actor_id=user["id"], org_id=user["org_id"],
             target_id=lid, ip=getattr(request.state, "client_ip", None))
    return Response(status_code=204)


@app.post("/api/library/{lid}/instantiate", status_code=201)
def instantiate_from_library(lid: str, request: Request,
                             engagement_id: str | None = None,
                             user: dict = Depends(auth.require_role("operator"))):
    """Create a finding by copying a library template (optionally into an
    engagement). This is the 'write once, reuse across reports' path."""
    item = db.get_library_item(lid, user["org_id"])
    if not item:
        raise HTTPException(status_code=404, detail="Library item not found")
    if engagement_id and not db.get_engagement(engagement_id, user["org_id"]):
        raise HTTPException(status_code=404, detail="Engagement not found")
    data = {k: item.get(k) for k in _LIBRARY_FIELDS if item.get(k) is not None}
    data["library_id"] = lid
    data.setdefault("status", "open")
    f = db.create_finding(user["org_id"], user["id"], engagement_id, data)
    db.audit("finding_from_library", actor_id=user["id"], org_id=user["org_id"],
             target_id=f["id"], ip=getattr(request.state, "client_ip", None))
    return f


# ── Evidence (upload / download, hashed, encrypted at rest) ──────

def _safe_filename(name: str) -> str:
    """Strip path and header-injection characters from a client filename."""
    name = (name or "evidence").replace("\\", "/").split("/")[-1]
    name = name.replace("\r", "").replace("\n", "").replace('"', "")
    return name[:255] or "evidence"


@app.get("/api/evidence")
def list_evidence(engagement_id: str | None = None, finding_id: str | None = None,
                  user: dict = Depends(auth.current_user)):
    return {"evidence": db.list_evidence(user["org_id"], engagement_id, finding_id)}


@app.post("/api/evidence", status_code=201)
async def upload_evidence(
    request: Request,
    file: UploadFile = File(...),
    engagement_id: str | None = Form(default=None),
    finding_id: str | None = Form(default=None),
    user: dict = Depends(auth.require_role("operator")),
):
    cap = evidence_store.MAX_EVIDENCE_BYTES
    contents = await file.read(cap + 1)
    if len(contents) > cap:
        raise HTTPException(status_code=413, detail="Evidence file too large")
    if not contents:
        raise HTTPException(status_code=400, detail="Empty file")
    if engagement_id and not db.get_engagement(engagement_id, user["org_id"]):
        raise HTTPException(status_code=404, detail="Engagement not found")
    if finding_id and not db.get_finding(finding_id, user["org_id"]):
        raise HTTPException(status_code=404, detail="Finding not found")

    filename = _safe_filename(file.filename)
    digest = evidence_store.sha256_hex(contents)
    meta = db.create_evidence(
        user["org_id"], user["id"], filename, file.content_type,
        len(contents), digest, engagement_id, finding_id,
    )
    evidence_store.save(user["org_id"], meta["id"], contents)

    # Link the evidence to the finding for one-click report assembly.
    if finding_id:
        f = db.get_finding(finding_id, user["org_id"])
        if f is not None:
            ev_ids = list(f.get("evidence_ids") or [])
            if meta["id"] not in ev_ids:
                ev_ids.append(meta["id"])
                db.update_finding(finding_id, user["org_id"], {"evidence_ids": ev_ids})

    db.audit("evidence_upload", actor_id=user["id"], org_id=user["org_id"],
             target_id=meta["id"], ip=getattr(request.state, "client_ip", None),
             detail=f"{filename} ({len(contents)} bytes, sha256={digest[:12]}…)")
    return meta


@app.get("/api/evidence/{eid}")
def get_evidence(eid: str, user: dict = Depends(auth.current_user)):
    meta = db.get_evidence(eid, user["org_id"])
    if not meta:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return meta


@app.get("/api/evidence/{eid}/download")
def download_evidence(eid: str, user: dict = Depends(auth.current_user)):
    meta = db.get_evidence(eid, user["org_id"])
    if not meta or not evidence_store.exists(user["org_id"], eid):
        raise HTTPException(status_code=404, detail="Evidence not found")
    data = evidence_store.load(user["org_id"], eid)
    # Integrity check against the recorded hash (chain-of-custody).
    if evidence_store.sha256_hex(data) != meta["sha256"]:
        raise HTTPException(status_code=500, detail="Evidence integrity check failed")
    filename = _safe_filename(meta.get("filename") or eid)
    # Always attachment + octet-stream so user-supplied content never renders
    # inline in the browser (defence against stored HTML/script in evidence).
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.delete("/api/evidence/{eid}", status_code=204)
def delete_evidence(eid: str, request: Request,
                    user: dict = Depends(auth.require_role("operator"))):
    if not db.delete_evidence(eid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Evidence not found")
    db.audit("evidence_delete", actor_id=user["id"], org_id=user["org_id"],
             target_id=eid, ip=getattr(request.state, "client_ip", None))
    return Response(status_code=204)


@app.delete("/api/evidence/{eid}/purge", status_code=204)
def purge_evidence(eid: str, request: Request,
                   user: dict = Depends(auth.require_role("admin"))):
    """Hard delete an evidence file (admin only) — removes bytes from disk."""
    if not db.purge_evidence(eid, user["org_id"]):
        raise HTTPException(status_code=404, detail="Evidence not found")
    evidence_store.remove(user["org_id"], eid)
    db.audit("evidence_purge", actor_id=user["id"], org_id=user["org_id"],
             target_id=eid, ip=getattr(request.state, "client_ip", None))
    return Response(status_code=204)


# Serve the web UI last, so it never shadows the /api routes above.
if _WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_WEB_DIR), html=True), name="web")
