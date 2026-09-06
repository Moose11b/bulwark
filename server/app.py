"""
Siege Tower — standalone FastAPI application.

Wraps the dependency-free planning engine in a small web service and serves the
planner UI. It exposes ONLY planning and documentation operations:

  GET  /api/bootstrap                     reference vocab, technique library, ranked plans
  POST /api/plan                          rank plans for one Rules-of-Engagement payload
  GET  /api/engagements                   list saved engagements (with progress)
  POST /api/engagements                   save a new engagement
  GET/PUT/DELETE /api/engagements/{id}    read / update / remove one
  GET  /api/engagements/{id}/report       compile the report (json | markdown)

SAFETY: nothing here executes a command, launches a tool, or connects to a
target, and nothing reads or moves data from a client's systems. The engine is
a standalone package with no network or subprocess access, so the planning
logic cannot act — it plans and documents only.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Response
from fastapi.staticfiles import StaticFiles

from siege_tower import BoxType, EngagementInput, Objective, build_plans
from siege_tower.render import plan_result_to_dict
from siege_tower.schema import Platform, Restriction, Tactic

from . import db
from .bootstrap import build_bootstrap
from .report import build_report, render_markdown


@asynccontextmanager
async def _lifespan(app: "FastAPI"):
    db.init_db()
    _bootstrap()  # warm the cache so the first request is fast
    yield


app = FastAPI(title="Siege Tower", version="0.1.0", lifespan=_lifespan)

_WEB_DIR = Path(__file__).resolve().parent.parent / "web"
_RESOLVED_WORKED = {"succeeded", "fell_back", "failed", "blocked"}


@lru_cache(maxsize=1)
def _bootstrap() -> dict:
    return build_bootstrap()


@lru_cache(maxsize=1)
def _pb_map() -> dict:
    return {p["technique_id"]: p for p in _bootstrap()["playbook"]}


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "siege-tower"}


@app.get("/api/bootstrap")
def bootstrap():
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
def plan(roe: dict = Body(...)):
    """Rank plans for a Rules-of-Engagement payload (a pure computation)."""
    try:
        objective = Objective(roe["objective"])
        box_type = BoxType(roe.get("box_type", "black"))
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid ROE: {exc}")
    inp = EngagementInput(
        objective=objective, box_type=box_type,
        scope_platforms=_coerce_list(roe.get("scope_platforms"), Platform),
        provided_access=list(roe.get("provided_access", [])),
        restrictions=_coerce_list(roe.get("restrictions"), Restriction),
        forbidden_technique_ids=list(roe.get("forbidden_technique_ids", [])),
        forbidden_tactics=_coerce_list(roe.get("forbidden_tactics"), Tactic),
        time_budget_hours=roe.get("time_budget_hours"),
        allow_evidence_removal=bool(roe.get("allow_evidence_removal", False)),
        emulate_adversary=roe.get("emulate_adversary"),
        objective_note=roe.get("objective_note"),
    )
    return plan_result_to_dict(build_plans(inp))


def _progress(eng: dict) -> dict:
    plan = eng.get("plan", [])
    logs = eng.get("logs", {})
    worked = sum(1 for s in plan if (logs.get(s.get("uid"), {}) or {}).get("outcome") in _RESOLVED_WORKED)
    total = len(plan)
    return {"steps": total, "worked": worked,
            "pct": round(100.0 * worked / total) if total else 0}


@app.get("/api/engagements")
def list_engagements():
    out = []
    for e in db.list_engagements():
        out.append({
            "id": e.get("id"), "name": e.get("name"), "client": e.get("client"),
            "objective": e.get("objective"), "box_type": e.get("box_type"),
            "status": e.get("status"), "updated_at": e.get("updated_at"),
            "progress": _progress(e),
        })
    return {"engagements": out}


@app.post("/api/engagements", status_code=201)
def create_engagement(data: dict = Body(...)):
    if not data.get("name"):
        raise HTTPException(status_code=400, detail="Engagement name is required")
    return db.create_engagement(data)


@app.get("/api/engagements/{eid}")
def get_engagement(eid: str):
    e = db.get_engagement(eid)
    if not e:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return e


@app.put("/api/engagements/{eid}")
def update_engagement(eid: str, data: dict = Body(...)):
    e = db.update_engagement(eid, data)
    if not e:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return e


@app.delete("/api/engagements/{eid}", status_code=204)
def delete_engagement(eid: str):
    if not db.delete_engagement(eid):
        raise HTTPException(status_code=404, detail="Engagement not found")
    return Response(status_code=204)


@app.get("/api/engagements/{eid}/report")
def engagement_report(eid: str, format: str = "json"):
    e = db.get_engagement(eid)
    if not e:
        raise HTTPException(status_code=404, detail="Engagement not found")
    rep = build_report(e, _pb_map())
    if format == "markdown":
        return Response(content=render_markdown(rep), media_type="text/markdown")
    return rep


# Serve the web UI last, so it never shadows the /api routes above.
if _WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_WEB_DIR), html=True), name="web")
