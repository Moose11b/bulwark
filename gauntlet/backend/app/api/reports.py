"""Report generation — one timeline, an output for every audience."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..engine import reporting

router = APIRouter(prefix="/api/sessions", tags=["reports"])


@router.post("/{session_id}/reports", response_model=schemas.ReportOut, status_code=201)
def generate_report(session_id: int, payload: schemas.ReportRequest, db: Session = Depends(get_db)):
    s = db.get(models.Session, session_id)
    if not s:
        raise HTTPException(404, "session not found")
    scenario = db.get(models.Scenario, s.scenario_id)
    env = db.get(models.Environment, scenario.environment_id)

    title, content = reporting.build_report(
        s, scenario, env, list(s.events), list(s.observations), payload.audience
    )
    report = models.Report(
        session_id=s.id, audience=payload.audience, title=title, content=content
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/{session_id}/reports", response_model=list[schemas.ReportOut])
def list_reports(session_id: int, db: Session = Depends(get_db)):
    return (
        db.execute(
            select(models.Report)
            .where(models.Report.session_id == session_id)
            .order_by(models.Report.id.desc())
        )
        .scalars()
        .all()
    )
