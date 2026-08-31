"""Program-level analytics (M4): coverage and improvement tracking."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..engine import program

router = APIRouter(prefix="/api/program", tags=["program"])


def _all(db: Session):
    scenarios = db.execute(select(models.Scenario)).scalars().all()
    sessions = db.execute(select(models.Session)).scalars().all()
    return scenarios, sessions


@router.get("/coverage")
def program_coverage(db: Session = Depends(get_db)):
    scenarios, sessions = _all(db)
    return program.build_program_coverage(scenarios, sessions)


@router.get("/improvements")
def program_improvements(db: Session = Depends(get_db)):
    scenarios, sessions = _all(db)
    return program.build_improvements(scenarios, sessions)
