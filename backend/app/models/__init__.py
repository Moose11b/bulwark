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
