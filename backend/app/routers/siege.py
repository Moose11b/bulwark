"""
Siege Tower router — red-team engagement planning and documentation.

This module exposes ONLY planning and documentation operations:
  * create/update/list engagements (the structured ROE + scope the team types),
  * generate ranked attack plans from that ROE (a pure, read-only computation
    over the engagement's own fields), and
  * record which plan the team selected.

It has, by design, NO endpoint that:
  * executes a command, launches a tool, or connects to any target, or
  * reads or transfers data from a client's systems.
Siege Tower suggests tooling and documents decisions; it never acts. The
`tests/test_siege_no_execution.py` guard asserts this module imports no
process/exec/target-connection machinery.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_org, get_current_user
from app.database import get_db
from app.models import Engagement, EngagementPlan, EngagementStatus, Organisation, User
from app.services import siege_adapter as adapter

router = APIRouter()


# ── Request models ───────────────────────────────────────────────

class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    objective: str
    box_type: str = "black"
    client_name: str | None = None
    authorization_ref: str | None = None
    scope_platforms: list[str] = Field(default_factory=list)
    in_scope_targets: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    provided_access: list[str] = Field(default_factory=list)
    restrictions: list[str] = Field(default_factory=list)
    forbidden_technique_ids: list[str] = Field(default_factory=list)
    forbidden_tactics: list[str] = Field(default_factory=list)
    time_budget_hours: float | None = None
    allow_evidence_removal: bool = False
    emulate_adversary: str | None = None
    roe_notes: str | None = None
    objective_note: str | None = None


class EngagementUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    objective: str | None = None
    box_type: str | None = None
    client_name: str | None = None
    authorization_ref: str | None = None
    scope_platforms: list[str] | None = None
    in_scope_targets: list[str] | None = None
    out_of_scope: list[str] | None = None
    provided_access: list[str] | None = None
    restrictions: list[str] | None = None
    forbidden_technique_ids: list[str] | None = None
    forbidden_tactics: list[str] | None = None
    time_budget_hours: float | None = None
    allow_evidence_removal: bool | None = None
    emulate_adversary: str | None = None
    roe_notes: str | None = None
    objective_note: str | None = None
    status: str | None = None


# ── Serialization ────────────────────────────────────────────────

def _engagement_dict(e: Engagement, include_plans: bool = False) -> dict:
    data = {
        "id": e.id,
        "name": e.name,
        "client_name": e.client_name,
        "authorization_ref": e.authorization_ref,
        "objective": e.objective,
        "box_type": e.box_type,
        "scope_platforms": e.scope_platforms,
        "in_scope_targets": e.in_scope_targets,
        "out_of_scope": e.out_of_scope,
        "provided_access": e.provided_access,
        "restrictions": e.restrictions,
        "forbidden_technique_ids": e.forbidden_technique_ids,
        "forbidden_tactics": e.forbidden_tactics,
        "time_budget_hours": e.time_budget_hours,
        "allow_evidence_removal": e.allow_evidence_removal,
        "emulate_adversary": e.emulate_adversary,
        "roe_notes": e.roe_notes,
        "objective_note": e.objective_note,
        "status": e.status.value if e.status else None,
        "last_plan_meta": e.last_plan_meta,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "updated_at": e.updated_at.isoformat() if e.updated_at else None,
    }
    if include_plans:
        data["plans"] = [_plan_dict(p) for p in sorted(e.plans, key=lambda p: p.plan_key)]
    return data


def _plan_dict(p: EngagementPlan) -> dict:
    return {
        "id": p.id,
        "plan_key": p.plan_key,
        "title": p.title,
        "fit_score": p.fit_score,
        "rationale": p.rationale,
        "steps": p.steps,
        "est_total_minutes": p.est_total_minutes,
        "within_time_budget": p.within_time_budget,
        "aggregate_noise": p.aggregate_noise,
        "max_difficulty": p.max_difficulty,
        "covered_tactics": p.covered_tactics,
        "warnings": p.warnings,
        "is_selected": p.is_selected,
        "generated_at": p.generated_at.isoformat() if p.generated_at else None,
    }


async def _get_owned_engagement(
    engagement_id: str, db: AsyncSession, org: Organisation
) -> Engagement:
    e = (await db.execute(
        select(Engagement).where(
            Engagement.id == engagement_id, Engagement.org_id == org.id
        )
    )).scalar_one_or_none()
    if not e:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return e


# ── Routes ───────────────────────────────────────────────────────

@router.get("/health")
async def health():
    return {
        "module": "siege",
        "status": "ok",
        "engine_available": adapter.ENGINE_AVAILABLE,
        "engine_version": adapter.ENGINE_VERSION,
    }


@router.get("/reference")
async def reference(user: User = Depends(get_current_user)):
    """Objectives, box types, platforms, restrictions, and tactics for the UI."""
    return adapter.reference_catalog()


@router.get("/playbook")
async def playbook(user: User = Depends(get_current_user)):
    """Technique tiles with suggested tooling (reference only, no commands)."""
    return {"plays": adapter.playbook_catalog()}


@router.get("/engagements")
async def list_engagements(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    rows = (await db.execute(
        select(Engagement).where(Engagement.org_id == org.id)
        .order_by(Engagement.created_at.desc())
    )).scalars().all()
    return {"engagements": [
        {
            "id": e.id, "name": e.name, "client_name": e.client_name,
            "objective": e.objective, "box_type": e.box_type,
            "status": e.status.value if e.status else None,
            "plan_count": len(e.plans),
            "updated_at": e.updated_at.isoformat() if e.updated_at else None,
        }
        for e in rows
    ]}


@router.post("/engagements", status_code=201)
async def create_engagement(
    body: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    _validate_objective_box(body.objective, body.box_type)
    e = Engagement(
        org_id=org.id,
        created_by_id=user.id,
        name=body.name,
        client_name=body.client_name,
        authorization_ref=body.authorization_ref,
        objective=body.objective,
        box_type=body.box_type,
        scope_platforms=body.scope_platforms,
        in_scope_targets=body.in_scope_targets,
        out_of_scope=body.out_of_scope,
        provided_access=body.provided_access,
        restrictions=body.restrictions,
        forbidden_technique_ids=body.forbidden_technique_ids,
        forbidden_tactics=body.forbidden_tactics,
        time_budget_hours=body.time_budget_hours,
        allow_evidence_removal=body.allow_evidence_removal,
        emulate_adversary=body.emulate_adversary,
        roe_notes=body.roe_notes,
        objective_note=body.objective_note,
        status=EngagementStatus.DRAFT,
        last_plan_meta={},
    )
    db.add(e)
    await db.commit()
    await db.refresh(e)
    return _engagement_dict(e)


@router.get("/engagements/{engagement_id}")
async def get_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    e = await _get_owned_engagement(engagement_id, db, org)
    return _engagement_dict(e, include_plans=True)


@router.patch("/engagements/{engagement_id}")
async def update_engagement(
    engagement_id: str,
    body: EngagementUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    e = await _get_owned_engagement(engagement_id, db, org)
    fields = body.model_dump(exclude_unset=True)

    if "objective" in fields or "box_type" in fields:
        _validate_objective_box(
            fields.get("objective", e.objective),
            fields.get("box_type", e.box_type),
        )
    if "status" in fields:
        try:
            e.status = EngagementStatus(fields.pop("status"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status")
    for key, value in fields.items():
        setattr(e, key, value)
    await db.commit()
    await db.refresh(e)
    return _engagement_dict(e, include_plans=True)


@router.delete("/engagements/{engagement_id}", status_code=204)
async def delete_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    e = await _get_owned_engagement(engagement_id, db, org)
    await db.delete(e)
    await db.commit()


@router.post("/engagements/{engagement_id}/generate")
async def generate_plans(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    """Generate ranked plans for the engagement's ROE.

    A pure computation over the engagement's own fields. Regenerating replaces
    the prior plan set (selection is cleared). No target is contacted.
    """
    e = await _get_owned_engagement(engagement_id, db, org)

    try:
        result = adapter.generate_plan_result(e)
    except adapter.EngineUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except adapter.InvalidEngagement as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Replace any previously generated plans for this engagement.
    existing = (await db.execute(
        select(EngagementPlan).where(EngagementPlan.engagement_id == e.id)
    )).scalars().all()
    for p in existing:
        await db.delete(p)

    now = datetime.utcnow()
    for option in result.options:
        db.add(EngagementPlan(
            engagement_id=e.id,
            org_id=org.id,
            generated_at=now,
            **adapter.option_to_row_fields(option),
        ))

    meta = adapter.result_meta(result)
    meta["generated_at"] = now.isoformat()
    e.last_plan_meta = meta
    if e.status == EngagementStatus.DRAFT:
        e.status = EngagementStatus.PLANNING

    await db.commit()
    await db.refresh(e)
    return _engagement_dict(e, include_plans=True)


@router.get("/engagements/{engagement_id}/plans")
async def list_plans(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    e = await _get_owned_engagement(engagement_id, db, org)
    rows = sorted(e.plans, key=lambda p: p.plan_key)
    return {"plans": [_plan_dict(p) for p in rows], "meta": e.last_plan_meta}


@router.post("/engagements/{engagement_id}/plans/{plan_key}/select")
async def select_plan(
    engagement_id: str,
    plan_key: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    e = await _get_owned_engagement(engagement_id, db, org)
    keys = {p.plan_key for p in e.plans}
    if plan_key not in keys:
        raise HTTPException(status_code=404, detail="Plan not found")
    await db.execute(
        update(EngagementPlan)
        .where(EngagementPlan.engagement_id == e.id)
        .values(is_selected=(EngagementPlan.plan_key == plan_key))
    )
    await db.commit()
    await db.refresh(e)
    return _engagement_dict(e, include_plans=True)


# ── Helpers ──────────────────────────────────────────────────────

def _validate_objective_box(objective: str, box_type: str) -> None:
    """Reject unknown objective/box values up front when the engine is present."""
    if not adapter.ENGINE_AVAILABLE:
        return
    ref = adapter.reference_catalog()
    valid_obj = {o["value"] for o in ref["objectives"]}
    valid_box = {b["value"] for b in ref["box_types"]}
    if objective not in valid_obj:
        raise HTTPException(status_code=400, detail=f"Unknown objective: {objective}")
    if box_type not in valid_box:
        raise HTTPException(status_code=400, detail=f"Unknown box type: {box_type}")
