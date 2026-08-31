"""Session conduct — the engine behind the facilitator console.

A session is one run of a scenario. These endpoints start it, present the
current inject and its branches, adjudicate player actions, capture
observations, and drive the branching MSEL forward — writing every step to the
tamper-evident timeline.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..engine import adjudication, msel
from ..timeline import append_event, verify_chain

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _get_session(db: Session, session_id: int) -> models.Session:
    s = db.get(models.Session, session_id)
    if not s:
        raise HTTPException(404, "session not found")
    return s


def _injects(db: Session, scenario_id: int) -> list[models.Inject]:
    return (
        db.execute(
            select(models.Inject)
            .where(models.Inject.scenario_id == scenario_id)
            .order_by(models.Inject.sequence)
        )
        .scalars()
        .all()
    )


def _current_inject(db: Session, s: models.Session):
    if not s.current_inject_code:
        return None
    return db.execute(
        select(models.Inject).where(
            models.Inject.scenario_id == s.scenario_id,
            models.Inject.code == s.current_inject_code,
        )
    ).scalar_one_or_none()


def _state(db: Session, s: models.Session) -> schemas.SessionState:
    scenario = db.get(models.Scenario, s.scenario_id)
    current = _current_inject(db, s)
    return schemas.SessionState(
        session=schemas.SessionSummary.model_validate(s),
        scenario=schemas.ScenarioSummary.model_validate(scenario),
        current_inject=schemas.InjectOut.model_validate(current) if current else None,
        available_branches=msel.available_branches(current) if current else [],
        timeline=[schemas.TimelineEventOut.model_validate(e) for e in s.events],
        observations=[schemas.ObservationOut.model_validate(o) for o in s.observations],
        terminal=msel.is_terminal(current) if current else False,
    )


def _fire_inject(db: Session, s: models.Session, inject: models.Inject) -> None:
    s.current_inject_code = inject.code
    append_event(
        db,
        s.id,
        kind="inject_fired",
        ref=inject.code,
        game_clock=inject.clock,
        payload={
            "title": inject.title,
            "channel": inject.channel,
            "narrative": inject.narrative,
            "techniques": inject.attack_techniques,
            "objective_code": inject.objective_code,
            "expected_actions": inject.expected_actions,
            "visible_to": inject.visible_to,
        },
    )


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #
@router.post("", response_model=schemas.SessionSummary, status_code=201)
def create_session(payload: schemas.SessionCreate, db: Session = Depends(get_db)):
    if not db.get(models.Scenario, payload.scenario_id):
        raise HTTPException(400, "scenario_id does not exist")
    s = models.Session(
        scenario_id=payload.scenario_id, name=payload.name, clock_mode=payload.clock_mode
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


@router.get("", response_model=list[schemas.SessionSummary])
def list_sessions(db: Session = Depends(get_db)):
    return db.execute(select(models.Session).order_by(models.Session.id.desc())).scalars().all()


@router.get("/{session_id}", response_model=schemas.SessionState)
def get_session_state(session_id: int, db: Session = Depends(get_db)):
    return _state(db, _get_session(db, session_id))


@router.post("/{session_id}/start", response_model=schemas.SessionState)
def start_session(session_id: int, db: Session = Depends(get_db)):
    s = _get_session(db, session_id)
    if s.status == "complete":
        raise HTTPException(409, "session already complete")
    injects = _injects(db, s.scenario_id)
    start = msel.get_start_inject(injects)
    if not start:
        raise HTTPException(400, "scenario has no injects")
    s.status = "running"
    s.started_at = datetime.now(timezone.utc)
    append_event(db, s.id, kind="status", payload={"status": "running"})
    _fire_inject(db, s, start)
    db.commit()
    db.refresh(s)
    return _state(db, s)


@router.post("/{session_id}/advance", response_model=schemas.SessionState)
def advance_session(session_id: int, decision: schemas.DecisionIn, db: Session = Depends(get_db)):
    s = _get_session(db, session_id)
    if s.status != "running":
        raise HTTPException(409, f"session is {s.status}, not running")
    current = _current_inject(db, s)
    if not current:
        raise HTTPException(409, "session has no current inject; start it first")

    branch = msel.resolve_branch(
        current, when=decision.when, trigger=decision.trigger, explicit_goto=decision.goto
    )
    if not branch:
        raise HTTPException(
            422,
            "no branch matched this decision — pick a branch, or pass an explicit "
            "'goto' to override as proctor",
        )

    append_event(
        db,
        s.id,
        kind="decision",
        ref=current.code,
        game_clock=current.clock,
        payload={
            "when": decision.when,
            "trigger": decision.trigger,
            "goto": branch.get("goto"),
            "label": branch.get("label", ""),
            "note": decision.note,
        },
    )

    goto = branch.get("goto")
    nxt = db.execute(
        select(models.Inject).where(
            models.Inject.scenario_id == s.scenario_id, models.Inject.code == goto
        )
    ).scalar_one_or_none()
    if not nxt:
        raise HTTPException(422, f"branch points to unknown inject '{goto}'")

    _fire_inject(db, s, nxt)
    db.commit()
    db.refresh(s)
    return _state(db, s)


@router.post("/{session_id}/adjudicate", response_model=schemas.AdjudicationOut)
def adjudicate_action(session_id: int, payload: schemas.AdjudicateIn, db: Session = Depends(get_db)):
    s = _get_session(db, session_id)
    scenario = db.get(models.Scenario, s.scenario_id)
    env = db.get(models.Environment, scenario.environment_id)
    current = _current_inject(db, s)

    target = payload.target_asset or (current.target_asset if current else "")
    techniques = payload.techniques or (current.attack_techniques if current else [])
    ruling = adjudication.adjudicate(env, techniques, target)

    event = append_event(
        db,
        s.id,
        kind="adjudication",
        ref=current.code if current else "",
        game_clock=current.clock if current else "",
        payload={**ruling, "description": payload.description},
    )
    db.commit()
    db.refresh(event)
    return schemas.AdjudicationOut(
        ruling=ruling, event=schemas.TimelineEventOut.model_validate(event)
    )


@router.post("/{session_id}/observe", response_model=schemas.ObservationOut, status_code=201)
def add_observation(session_id: int, payload: schemas.ObservationIn, db: Session = Depends(get_db)):
    s = _get_session(db, session_id)
    obs = models.Observation(session_id=s.id, **payload.model_dump())
    db.add(obs)
    db.flush()
    append_event(
        db,
        s.id,
        kind="observation",
        ref=payload.objective_code,
        payload={"rating": payload.rating, "note": payload.note, "observation_id": obs.id},
    )
    db.commit()
    db.refresh(obs)
    return obs


@router.post("/{session_id}/note", response_model=schemas.TimelineEventOut, status_code=201)
def add_note(session_id: int, payload: schemas.NoteIn, db: Session = Depends(get_db)):
    s = _get_session(db, session_id)
    current = _current_inject(db, s)
    event = append_event(
        db,
        s.id,
        kind="note",
        ref=current.code if current else "",
        game_clock=current.clock if current else "",
        payload={"text": payload.text},
    )
    db.commit()
    db.refresh(event)
    return event


@router.post("/{session_id}/pause", response_model=schemas.SessionState)
def pause_session(session_id: int, db: Session = Depends(get_db)):
    s = _get_session(db, session_id)
    s.status = "paused"
    append_event(db, s.id, kind="status", payload={"status": "paused"})
    db.commit()
    db.refresh(s)
    return _state(db, s)


@router.post("/{session_id}/resume", response_model=schemas.SessionState)
def resume_session(session_id: int, db: Session = Depends(get_db)):
    s = _get_session(db, session_id)
    if s.status == "complete":
        raise HTTPException(409, "session already complete")
    s.status = "running"
    append_event(db, s.id, kind="status", payload={"status": "running"})
    db.commit()
    db.refresh(s)
    return _state(db, s)


@router.post("/{session_id}/complete", response_model=schemas.SessionState)
def complete_session(session_id: int, db: Session = Depends(get_db)):
    s = _get_session(db, session_id)
    s.status = "complete"
    s.completed_at = datetime.now(timezone.utc)
    append_event(db, s.id, kind="status", payload={"status": "complete"})
    db.commit()
    db.refresh(s)
    return _state(db, s)


@router.get("/{session_id}/verify")
def verify_timeline(session_id: int, db: Session = Depends(get_db)):
    s = _get_session(db, session_id)
    valid = verify_chain(list(s.events))
    return {"session_id": s.id, "events": len(s.events), "chain_valid": valid}
