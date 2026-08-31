"""Sandbox & real-time (M4): authorization-gated live/technical injects.

A live inject executes a technical action through the range adapter and feeds
the telemetry into adjudication. It is refused unless the session carries a
valid, unexpired authorization grant whose scope covers the target — the
guardrail that keeps operational modes from touching anything out of scope.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..engine import range_adapter
from ..timeline import append_event

router = APIRouter(prefix="/api/sessions", tags=["live"])

LIVE_MODES = ("sandbox", "real_time")


def _target_in_scope(scope: list, target: str) -> bool:
    return "*" in (scope or []) or (target in (scope or []))


def _authorization_error(session: models.Session, target: str) -> str | None:
    """Return a reason string if the session may not run a live inject, else None."""
    if session.mode not in LIVE_MODES:
        return (f"session mode is '{session.mode}'; live injects require a sandbox or "
                "real_time session")
    if not session.auth_expires_at:
        return "no authorization on this session — grant one via /authorize first"
    if session.auth_expires_at <= datetime.utcnow():
        return "authorization has expired — re-authorize before running live injects"
    if not _target_in_scope(session.auth_scope, target):
        return f"target '{target}' is outside the authorized scope {session.auth_scope}"
    return None


@router.post("/{session_id}/authorize", response_model=schemas.SessionSummary)
def authorize_session(session_id: int, payload: schemas.AuthorizeIn, db: Session = Depends(get_db)):
    s = db.get(models.Session, session_id)
    if not s:
        raise HTTPException(404, "session not found")
    expires = datetime.utcnow() + timedelta(minutes=max(1, payload.ttl_minutes))
    s.auth_scope = payload.scope
    s.authorized_by = payload.authorized_by
    s.auth_expires_at = expires
    append_event(db, s.id, kind="authorization", payload={
        "scope": payload.scope,
        "authorized_by": payload.authorized_by,
        "note": payload.note,
        "expires_at": expires.isoformat(),
    })
    db.commit()
    db.refresh(s)
    return s


@router.post("/{session_id}/live-inject", response_model=schemas.LiveInjectOut)
def live_inject(session_id: int, payload: schemas.LiveInjectIn, db: Session = Depends(get_db)):
    s = db.get(models.Session, session_id)
    if not s:
        raise HTTPException(404, "session not found")

    reason = _authorization_error(s, payload.target)
    if reason:
        raise HTTPException(403, reason)

    scenario = db.get(models.Scenario, s.scenario_id)
    env = db.get(models.Environment, scenario.environment_id)

    result = range_adapter.get_adapter().execute(env, payload.technique, payload.target)

    current = s.current_inject_code or ""
    event = append_event(db, s.id, kind="live_inject", ref=current, payload={
        "action": payload.action,
        "technique": payload.technique,
        "target": payload.target,
        "mode": s.mode,
        "adapter": result["adapter"],
        "telemetry": result["telemetry"],
        "detected": result["ruling"]["detected"],
        "rationale": result["ruling"]["rationale"],
        "note": result["note"],
    })
    db.commit()
    db.refresh(event)
    return schemas.LiveInjectOut(
        executed=result["executed"],
        adapter=result["adapter"],
        telemetry=result["telemetry"],
        ruling=result["ruling"],
        event=schemas.TimelineEventOut.model_validate(event),
    )
