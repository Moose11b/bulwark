"""Multi-cell & parallel (M3): fog-of-war views and cross-session roll-up."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..engine import rollup, visibility

router = APIRouter(tags=["multicell"])


def _cell_name(scenario, cell_key: str) -> str:
    for c in scenario.cells or []:
        if c.get("key") == cell_key:
            return c.get("name", cell_key)
    return cell_key


@router.get("/api/sessions/{session_id}/cell/{cell_key}", response_model=schemas.CellSessionView)
def cell_session_view(session_id: int, cell_key: str, db: Session = Depends(get_db)):
    """The session as one cell may see it — injects addressed to it only, no
    White Cell machinery (unless the cell is itself a control cell)."""
    s = db.get(models.Session, session_id)
    if not s:
        raise HTTPException(404, "session not found")
    scenario = db.get(models.Scenario, s.scenario_id)

    current = None
    if s.current_inject_code:
        current = db.execute(
            select(models.Inject).where(
                models.Inject.scenario_id == s.scenario_id,
                models.Inject.code == s.current_inject_code,
            )
        ).scalar_one_or_none()

    visible_current = visibility.current_inject_for_cell(current, scenario, cell_key)
    visible_events = visibility.filter_timeline(s.events, scenario, cell_key)

    return schemas.CellSessionView(
        cell_key=cell_key,
        cell_name=_cell_name(scenario, cell_key),
        can_see_all=visibility.is_control_cell(scenario, cell_key),
        session=schemas.SessionSummary.model_validate(s),
        current_inject=schemas.InjectOut.model_validate(visible_current) if visible_current else None,
        timeline=[schemas.TimelineEventOut.model_validate(e) for e in visible_events],
        objectives=[schemas.ObjectiveOut.model_validate(o) for o in scenario.objectives],
    )


@router.get("/api/environments/{env_id}/view/{cell_key}")
def environment_cell_view(env_id: int, cell_key: str, scenario_id: int, db: Session = Depends(get_db)):
    """A per-cell redacted environment — the white/grey/black-box view. The
    ``scenario_id`` query param supplies the cell roster used to resolve the
    cell's control status."""
    env = db.get(models.Environment, env_id)
    if not env:
        raise HTTPException(404, "environment not found")
    scenario = db.get(models.Scenario, scenario_id)
    if not scenario:
        raise HTTPException(400, "scenario_id does not exist")
    return visibility.filter_environment(env, scenario, cell_key)


@router.get("/api/scenarios/{scenario_id}/rollup", response_model=schemas.RollupOut)
def scenario_rollup(scenario_id: int, db: Session = Depends(get_db)):
    """Compare every run of a scenario — the parallel / program view."""
    scenario = db.get(models.Scenario, scenario_id)
    if not scenario:
        raise HTTPException(404, "scenario not found")
    sessions = (
        db.execute(
            select(models.Session)
            .where(models.Session.scenario_id == scenario_id)
            .order_by(models.Session.id)
        )
        .scalars()
        .all()
    )
    return rollup.build_rollup(scenario, sessions)
