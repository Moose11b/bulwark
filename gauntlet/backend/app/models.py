"""ORM models for the tabletop-exercise domain.

The vocabulary deliberately mirrors how exercise practitioners talk (HSEEP /
NIST SP 800-84), so an object on screen matches an object in an exercise
director's head: Environment, Scenario, Inject (the scene), Session (one run),
TimelineEvent (the tamper-evident record), Observation, Report.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Environment(Base):
    """The system under test — everything the team chooses to feed in.

    ``box_type`` sets the default knowledge posture (white / grey / black);
    per-audience redaction is expressed through the ``visibility`` map, which
    lists the environment keys each cell is allowed to see.
    """

    __tablename__ = "environments"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    sector: Mapped[str] = mapped_column(String(120), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    box_type: Mapped[str] = mapped_column(String(20), default="grey")  # white|grey|black

    assets: Mapped[list] = mapped_column(JSON, default=list)
    controls: Mapped[list] = mapped_column(JSON, default=list)
    detections: Mapped[list] = mapped_column(JSON, default=list)
    playbooks: Mapped[list] = mapped_column(JSON, default=list)
    policies: Mapped[list] = mapped_column(JSON, default=list)
    personnel: Mapped[list] = mapped_column(JSON, default=list)
    deception_assets: Mapped[list] = mapped_column(JSON, default=list)
    crown_jewels: Mapped[list] = mapped_column(JSON, default=list)
    visibility: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scenarios: Mapped[list["Scenario"]] = relationship(back_populates="environment")


class Scenario(Base):
    """The exercise premise: a threat actor, a narrative arc, and its MSEL."""

    __tablename__ = "scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id"))
    name: Mapped[str] = mapped_column(String(200))
    threat_actor: Mapped[str] = mapped_column(String(200), default="")
    narrative: Mapped[str] = mapped_column(Text, default="")
    scope: Mapped[str] = mapped_column(Text, default="")
    rules_of_engagement: Mapped[str] = mapped_column(Text, default="")
    cells: Mapped[list] = mapped_column(JSON, default=list)  # roles & fog-of-war
    exercise_type: Mapped[str] = mapped_column(String(40), default="tabletop")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    environment: Mapped["Environment"] = relationship(back_populates="scenarios")
    objectives: Mapped[list["Objective"]] = relationship(
        back_populates="scenario", cascade="all, delete-orphan"
    )
    injects: Mapped[list["Inject"]] = relationship(
        back_populates="scenario", cascade="all, delete-orphan"
    )


class Objective(Base):
    """A measurable goal plus its Exercise Evaluation Guide."""

    __tablename__ = "objectives"

    id: Mapped[int] = mapped_column(primary_key=True)
    scenario_id: Mapped[int] = mapped_column(ForeignKey("scenarios.id"))
    code: Mapped[str] = mapped_column(String(40))  # e.g. "OBJ-2"
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    success_criteria: Mapped[str] = mapped_column(Text, default="")
    eeg: Mapped[list] = mapped_column(JSON, default=list)  # evaluation-guide items

    scenario: Mapped["Scenario"] = relationship(back_populates="objectives")


class Inject(Base):
    """One scene in the Master Scenario Events List.

    ``branches`` is the choose-your-own-adventure spine — a list of
    ``{when, trigger?, after?, goto, label}`` rules routing to the next inject
    on a player action, a game-clock timeout, or the proctor's choice.
    """

    __tablename__ = "injects"

    id: Mapped[int] = mapped_column(primary_key=True)
    scenario_id: Mapped[int] = mapped_column(ForeignKey("scenarios.id"))
    code: Mapped[str] = mapped_column(String(40))  # human id, e.g. "INJ-04"
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(240))
    channel: Mapped[str] = mapped_column(String(40), default="briefing")
    clock: Mapped[str] = mapped_column(String(20), default="")  # game time, e.g. "T+00:35"
    narrative: Mapped[str] = mapped_column(Text, default="")
    visible_to: Mapped[list] = mapped_column(JSON, default=list)
    expected_actions: Mapped[list] = mapped_column(JSON, default=list)
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list)
    target_asset: Mapped[str] = mapped_column(String(120), default="")
    objective_code: Mapped[str] = mapped_column(String(40), default="")
    branches: Mapped[list] = mapped_column(JSON, default=list)
    is_start: Mapped[bool] = mapped_column(default=False)

    scenario: Mapped["Scenario"] = relationship(back_populates="injects")


class Session(Base):
    """One run of a scenario. Holds live state the console reads and drives."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    scenario_id: Mapped[int] = mapped_column(ForeignKey("scenarios.id"))
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="setup")  # setup|running|paused|complete
    clock_mode: Mapped[str] = mapped_column(String(20), default="compressed")
    current_inject_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    events: Mapped[list["TimelineEvent"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="TimelineEvent.seq"
    )
    observations: Mapped[list["Observation"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class TimelineEvent(Base):
    """Append-only, hash-chained record of everything that happened.

    Each event stores the previous event's hash and its own, so the timeline is
    tamper-evident — the property that makes a report defensible for audit.
    """

    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"))
    seq: Mapped[int] = mapped_column(Integer)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    game_clock: Mapped[str] = mapped_column(String(20), default="")
    kind: Mapped[str] = mapped_column(String(30))  # inject_fired|decision|adjudication|note|observation|status
    ref: Mapped[str] = mapped_column(String(60), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="")

    session: Mapped["Session"] = relationship(back_populates="events")


class Observation(Base):
    """An evaluator's note, tied to an objective and a moment on the timeline."""

    __tablename__ = "observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"))
    objective_code: Mapped[str] = mapped_column(String(40), default="")
    rating: Mapped[str] = mapped_column(String(20), default="note")  # met|partial|missed|note
    note: Mapped[str] = mapped_column(Text, default="")
    timeline_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    session: Mapped["Session"] = relationship(back_populates="observations")


class Report(Base):
    """A rendered output for one audience, generated from the timeline."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"))
    audience: Mapped[str] = mapped_column(String(40))  # executive|technical|grc|training
    title: Mapped[str] = mapped_column(String(240))
    content: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
