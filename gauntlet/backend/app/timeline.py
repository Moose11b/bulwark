"""Append-only, hash-chained timeline helper.

Every material moment in a session is written here. Each event hashes the
previous event's hash together with its own canonical content, so any later
edit to the record breaks the chain — the property that makes an exercise
report defensible for audit.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .models import TimelineEvent


def _hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def append_event(
    db: DbSession,
    session_id: int,
    kind: str,
    payload: dict,
    ref: str = "",
    game_clock: str = "",
) -> TimelineEvent:
    """Create, hash-chain, and persist one timeline event."""
    last = db.execute(
        select(TimelineEvent)
        .where(TimelineEvent.session_id == session_id)
        .order_by(TimelineEvent.seq.desc())
        .limit(1)
    ).scalar_one_or_none()

    seq = (last.seq + 1) if last else 1
    prev_hash = last.hash if last else ""
    # Naive UTC so the value hashed here round-trips byte-identically out of the
    # database when the chain is later re-verified.
    at = datetime.utcnow()

    canonical = json.dumps(
        {
            "seq": seq,
            "kind": kind,
            "ref": ref,
            "game_clock": game_clock,
            "payload": payload,
            "at": at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    event = TimelineEvent(
        session_id=session_id,
        seq=seq,
        at=at,
        game_clock=game_clock,
        kind=kind,
        ref=ref,
        payload=payload,
        prev_hash=prev_hash,
        hash=_hash(prev_hash, canonical),
    )
    db.add(event)
    db.flush()
    return event


def verify_chain(events: list[TimelineEvent]) -> bool:
    """Return True if the ordered events form an unbroken hash chain."""
    prev_hash = ""
    for e in sorted(events, key=lambda x: x.seq):
        canonical = json.dumps(
            {
                "seq": e.seq,
                "kind": e.kind,
                "ref": e.ref,
                "game_clock": e.game_clock,
                "payload": e.payload,
                "at": e.at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if e.prev_hash != prev_hash or e.hash != _hash(prev_hash, canonical):
            return False
        prev_hash = e.hash
    return True
