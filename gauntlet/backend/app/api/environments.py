"""Environment intake — the 'feed it what you know' surface."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db

router = APIRouter(prefix="/api/environments", tags=["environments"])


@router.post("", response_model=schemas.EnvironmentOut, status_code=201)
def create_environment(payload: schemas.EnvironmentCreate, db: Session = Depends(get_db)):
    env = models.Environment(**payload.model_dump())
    db.add(env)
    db.commit()
    db.refresh(env)
    return env


@router.get("", response_model=list[schemas.EnvironmentSummary])
def list_environments(db: Session = Depends(get_db)):
    return db.execute(select(models.Environment).order_by(models.Environment.id)).scalars().all()


@router.get("/{env_id}", response_model=schemas.EnvironmentOut)
def get_environment(env_id: int, db: Session = Depends(get_db)):
    env = db.get(models.Environment, env_id)
    if not env:
        raise HTTPException(404, "environment not found")
    return env
