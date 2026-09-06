import uuid
from datetime import datetime
from typing import Any
from sqlalchemy import (
    BigInteger, Boolean, DateTime, Enum, Float, ForeignKey,
    Integer, String, Text, func, JSON
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base
import enum


def now() -> datetime:
    return datetime.utcnow()


def new_uuid() -> str:
    return str(uuid.uuid4())


# ── Enums ────────────────────────────────────────────────────────

class PlanTier(str, enum.Enum):
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    NMAP = "nmap"
    SSL = "ssl"
    HEADERS = "headers"
    DNS = "dns"
    NIKTO = "nikto"
    NUCLEI = "nuclei"
    SHODAN = "shodan"
    OSINT = "osint"
    EXPOSURE = "exposure"
    FULL = "full"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"


class RiskTier(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ── Organisation ─────────────────────────────────────────────────

class Organisation(Base):
    __tablename__ = "organisations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    clerk_org_id: Mapped[str | None] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    plan: Mapped[PlanTier] = mapped_column(
        Enum(PlanTier), default=PlanTier.STARTER
    )
    stripe_customer_id: Mapped[str | None] = mapped_column(String, unique=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String)
    scan_count_month: Mapped[int] = mapped_column(Integer, default=0)
    scan_limit: Mapped[int] = mapped_column(Integer, default=25)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)

    users: Mapped[list["User"]] = relationship(back_populates="org")
    assets: Mapped[list["Asset"]] = relationship(back_populates="org")
    scans: Mapped[list["Scan"]] = relationship(back_populates="org")
    alert_configs: Mapped[list["AlertConfig"]] = relationship(back_populates="org")


# ── User ─────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    clerk_user_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

    org: Mapped["Organisation"] = relationship(back_populates="users")
    scans: Mapped[list["Scan"]] = relationship(back_populates="created_by")


# ── Asset ─────────────────────────────────────────────────────────

class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    target: Mapped[str] = mapped_column(String(512))
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType))
    risk_tier: Mapped[RiskTier] = mapped_column(Enum(RiskTier), default=RiskTier.MEDIUM)
    owner: Mapped[str | None] = mapped_column(String(255))
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    notes: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)

    org: Mapped["Organisation"] = relationship(back_populates="assets")
    scans: Mapped[list["Scan"]] = relationship(back_populates="asset")
    schedule: Mapped["ScanSchedule | None"] = relationship(
        back_populates="asset", uselist=False
    )


# ── Scan ──────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True)
    created_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    target: Mapped[str] = mapped_column(String(512))
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType))
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.QUEUED, index=True
    )
    celery_task_id: Mapped[str | None] = mapped_column(String)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    progress_message: Mapped[str] = mapped_column(String(512), default="Queued")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    finding_counts: Mapped[dict] = mapped_column(JSONB, default=dict)
    raw_results: Mapped[dict | None] = mapped_column(JSONB)
    scan_options: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)

    org: Mapped["Organisation"] = relationship(back_populates="scans")
    asset: Mapped["Asset | None"] = relationship(back_populates="scans")
    created_by: Mapped["User"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


# ── Finding ───────────────────────────────────────────────────────

class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)

    # Identity
    title: Mapped[str] = mapped_column(String(512))
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(64))

    # Classification
    severity: Mapped[Severity] = mapped_column(Enum(Severity), index=True)
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    epss_score: Mapped[float | None] = mapped_column(Float)
    is_in_kev: Mapped[bool] = mapped_column(Boolean, default=False)

    # OWASP / Kill Chain
    owasp_category: Mapped[str | None] = mapped_column(String(4))
    killchain_phase: Mapped[str | None] = mapped_column(String(64))
    mitre_technique_id: Mapped[str | None] = mapped_column(String(16))
    mitre_tactic: Mapped[str | None] = mapped_column(String(64))

    # Compliance
    pci_dss: Mapped[list] = mapped_column(JSONB, default=list)
    iso_27001: Mapped[list] = mapped_column(JSONB, default=list)
    nist_csf: Mapped[list] = mapped_column(JSONB, default=list)
    cis_v8: Mapped[list] = mapped_column(JSONB, default=list)

    # Detail
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSONB, default=list)
    raw_output: Mapped[str | None] = mapped_column(Text)

    # Tracking
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.OPEN, index=True
    )
    assigned_to: Mapped[str | None] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Cross-scan identity. Stable for the same issue on the same target, so a
    # finding can be followed from one scan to the next.
    fingerprint: Mapped[str | None] = mapped_column(String(32), index=True)
    # False when this fingerprint was already present in the previous scan of
    # the same asset/target — i.e. the finding is recurring, not newly found.
    is_new: Mapped[bool] = mapped_column(Boolean, default=True)

    # first_seen carries forward from the earliest scan that saw this
    # fingerprint; last_seen is always the current scan.
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=now)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    comments: Mapped[list["FindingComment"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class AuthType(str, enum.Enum):
    """How a scan credential is presented to the target."""
    COOKIE = "cookie"          # Cookie: <value>
    BEARER = "bearer"          # Authorization: Bearer <value>
    HEADER = "header"          # <header_name>: <value>


class AssetCredential(Base):
    """A credential letting scanners reach an asset's authenticated surface.

    Kept in its own table rather than as columns on Asset so that listing or
    editing assets never loads the ciphertext — the secret is read only by the
    scan path that actually needs it.

    The secret is encrypted with CREDENTIAL_ENCRYPTION_KEY (see core/secrets.py)
    and is never returned by the API in any form.
    """
    __tablename__ = "asset_credentials"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, index=True
    )
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)

    auth_type: Mapped[AuthType] = mapped_column(Enum(AuthType))
    # Header name for AuthType.HEADER; ignored for cookie/bearer.
    header_name: Mapped[str | None] = mapped_column(String(64))
    secret_encrypted: Mapped[str] = mapped_column(Text)

    created_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime)


class FindingComment(Base):
    __tablename__ = "finding_comments"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

    finding: Mapped["Finding"] = relationship(back_populates="comments")


# ── Scan schedule ─────────────────────────────────────────────────

class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id"), unique=True, index=True
    )
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType))
    cron_expression: Mapped[str] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime)
    redbeat_key: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

    asset: Mapped["Asset"] = relationship(back_populates="schedule")


# ── Alert config ──────────────────────────────────────────────────

class AlertConfig(Base):
    __tablename__ = "alert_configs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    channel: Mapped[str] = mapped_column(String(32))
    webhook_url: Mapped[str | None] = mapped_column(String(512))
    email_to: Mapped[str | None] = mapped_column(String(320))
    min_severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.HIGH)
    on_new_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    on_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    on_new_cve: Mapped[bool] = mapped_column(Boolean, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

    org: Mapped["Organisation"] = relationship(back_populates="alert_configs")


# ── Audit log ─────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)


# ── Threat intelligence ───────────────────────────────────────────

class MitreTechnique(Base):
    """MITRE ATT&CK technique synced from the live STIX 2.1 feed."""
    __tablename__ = "mitre_techniques"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    technique_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)  # e.g. T1190
    name: Mapped[str] = mapped_column(String(255))
    tactic: Mapped[str | None] = mapped_column(String(128), index=True)
    tactic_ids: Mapped[list] = mapped_column(JSONB, default=list)
    description: Mapped[str | None] = mapped_column(Text)
    platforms: Mapped[list] = mapped_column(JSONB, default=list)
    detection: Mapped[str | None] = mapped_column(Text)
    mitigations: Mapped[list] = mapped_column(JSONB, default=list)
    url: Mapped[str | None] = mapped_column(String(512))
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    stix_version: Mapped[str | None] = mapped_column(String(32))
    synced_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class IOC(Base):
    """Indicator of Compromise from threat intel feeds (OTX, etc.)."""
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    indicator: Mapped[str] = mapped_column(String(512), index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)  # domain, ip, url, hash, cve
    source: Mapped[str] = mapped_column(String(64))  # otx, virustotal, manual
    threat_type: Mapped[str | None] = mapped_column(String(128))
    pulse_name: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    references: Mapped[list] = mapped_column(JSONB, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)


class ThreatFeedSync(Base):
    """Tracks the status of each threat feed synchronisation run."""
    __tablename__ = "threat_feed_syncs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    feed_name: Mapped[str] = mapped_column(String(64), index=True)  # mitre_attack, otx, kev
    status: Mapped[str] = mapped_column(String(32))  # success, failed, running
    records_synced: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)


# ── Siege Tower: red-team engagement planning ─────────────────────
# Siege Tower is a planning and documentation module. These tables hold only
# what the red team enters — the Rules of Engagement, the scope, the generated
# plans, and (later) the operator's notes on steps taken. They never hold data
# pulled from a client's systems, and nothing here executes anything: the
# module suggests and records, it does not act.

class EngagementStatus(str, enum.Enum):
    DRAFT = "draft"          # ROE/scope being entered
    PLANNING = "planning"    # plans generated, team choosing an approach
    ACTIVE = "active"        # engagement underway, steps being documented
    COMPLETE = "complete"    # finished, report compiled
    ARCHIVED = "archived"


class Engagement(Base):
    """A red-team engagement: its structured ROE, scope, and status.

    Objective and box type are stored as plain strings (the Siege Tower engine's
    vocabulary) rather than DB enums so the engine can add objectives without a
    schema migration. `status` is a DB enum because its set is stable.
    """
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)
    created_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"))

    name: Mapped[str] = mapped_column(String(255))
    client_name: Mapped[str | None] = mapped_column(String(255))
    # A reference (id/URL/filename) to the signed authorization — never the
    # document contents. Present so a plan can be traced to its authority.
    authorization_ref: Mapped[str | None] = mapped_column(String(512))

    # ── Structured Rules of Engagement (maps to the engine's EngagementInput)
    objective: Mapped[str] = mapped_column(String(64))
    box_type: Mapped[str] = mapped_column(String(16), default="black")
    scope_platforms: Mapped[list] = mapped_column(JSONB, default=list)
    in_scope_targets: Mapped[list] = mapped_column(JSONB, default=list)
    out_of_scope: Mapped[list] = mapped_column(JSONB, default=list)
    provided_access: Mapped[list] = mapped_column(JSONB, default=list)
    restrictions: Mapped[list] = mapped_column(JSONB, default=list)
    forbidden_technique_ids: Mapped[list] = mapped_column(JSONB, default=list)
    forbidden_tactics: Mapped[list] = mapped_column(JSONB, default=list)
    time_budget_hours: Mapped[float | None] = mapped_column(Float)
    allow_evidence_removal: Mapped[bool] = mapped_column(Boolean, default=False)
    emulate_adversary: Mapped[str | None] = mapped_column(String(64))
    roe_notes: Mapped[str | None] = mapped_column(Text)
    objective_note: Mapped[str | None] = mapped_column(Text)

    status: Mapped[EngagementStatus] = mapped_column(
        Enum(EngagementStatus), default=EngagementStatus.DRAFT, index=True
    )
    # Result-level metadata from the last plan generation (goal capability,
    # starting capabilities, and which plays the ROE excluded and why).
    last_plan_meta: Mapped[dict] = mapped_column(JSONB, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)

    plans: Mapped[list["EngagementPlan"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )


class EngagementPlan(Base):
    """One ranked, generated attack plan persisted for an engagement.

    A regeneration replaces the prior set for the engagement. `steps` is the
    serialized, drill-down plan (technique, objective, suggested tooling,
    fallbacks) exactly as the engine produced it.
    """
    __tablename__ = "engagement_plans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)

    plan_key: Mapped[str] = mapped_column(String(32))   # e.g. "plan-1"
    title: Mapped[str] = mapped_column(String(512))
    fit_score: Mapped[float] = mapped_column(Float, default=0.0)
    rationale: Mapped[list] = mapped_column(JSONB, default=list)
    steps: Mapped[list] = mapped_column(JSONB, default=list)
    est_total_minutes: Mapped[int] = mapped_column(Integer, default=0)
    within_time_budget: Mapped[bool | None] = mapped_column(Boolean)
    aggregate_noise: Mapped[float] = mapped_column(Float, default=0.0)
    max_difficulty: Mapped[int] = mapped_column(Integer, default=0)
    covered_tactics: Mapped[list] = mapped_column(JSONB, default=list)
    warnings: Mapped[list] = mapped_column(JSONB, default=list)

    # The plan the team chose to run (at most one per engagement).
    is_selected: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    generated_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

    engagement: Mapped["Engagement"] = relationship(back_populates="plans")


class LogOutcome(str, enum.Enum):
    """What happened when the team worked a step."""
    NOT_STARTED = "not_started"
    ATTEMPTED = "attempted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    FELL_BACK = "fell_back"      # primary failed, a fallback technique was used
    BLOCKED = "blocked"          # stopped by a control / ROE / scope boundary
    SKIPPED = "skipped"


class EngagementLog(Base):
    """One documented action taken during an engagement.

    This is the "document as you go" record. Entries reference a plan step by
    its stable identifiers (plan_key / technique_id / step_index) rather than a
    foreign key, so regenerating the plan set never deletes the team's history.

    It holds only what the operator writes: an outcome, notes, and *references*
    to where evidence lives (filenames, ticket ids) — never evidence data or
    anything pulled from the client's systems. Nothing here executes.
    """
    __tablename__ = "engagement_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), index=True)
    operator_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))

    # Which plan step this documents (denormalized, nullable for ad-hoc notes).
    plan_key: Mapped[str | None] = mapped_column(String(32))
    step_index: Mapped[int | None] = mapped_column(Integer)
    technique_id: Mapped[str | None] = mapped_column(String(16), index=True)

    title: Mapped[str] = mapped_column(String(512))
    outcome: Mapped[LogOutcome] = mapped_column(
        Enum(LogOutcome), default=LogOutcome.ATTEMPTED, index=True
    )
    notes: Mapped[str | None] = mapped_column(Text)
    # References to evidence stored elsewhere (paths, filenames, ticket ids) —
    # not the evidence itself.
    evidence_refs: Mapped[list] = mapped_column(JSONB, default=list)
    # Operator-noted hosts/IPs this action touched (free text the team types).
    targets: Mapped[list] = mapped_column(JSONB, default=list)

    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)
