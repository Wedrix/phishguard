from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class UserAccount(Base):
    __tablename__ = "user_account"
    __table_args__ = (
        CheckConstraint(
            "role IN ('REGISTERED_USER', 'ANALYST', 'ADMINISTRATOR', 'RESEARCHER')",
            name="ck_user_account_role",
        ),
        CheckConstraint(
            "is_canonical_admin = false OR (role = 'ADMINISTRATOR' AND disabled_at IS NULL)",
            name="ck_user_account_canonical_active_admin",
        ),
        Index(
            "uq_user_account_canonical_admin",
            "is_canonical_admin",
            unique=True,
            postgresql_where=text("is_canonical_admin"),
            sqlite_where=text("is_canonical_admin = 1"),
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    identity_subject: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    email_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="REGISTERED_USER")
    email_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_canonical_admin: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    scan_retention_days: Mapped[int | None] = mapped_column(Integer)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now, onupdate=now)


class RoleRequest(Base):
    __tablename__ = "role_request"
    __table_args__ = (
        CheckConstraint(
            "requested_role IN ('ANALYST', 'RESEARCHER')",
            name="ck_role_request_requested_role",
        ),
        CheckConstraint(
            "state IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED')",
            name="ck_role_request_state",
        ),
        Index(
            "uq_role_request_pending_user",
            "user_id",
            unique=True,
            postgresql_where=text("state = 'PENDING'"),
            sqlite_where=text("state = 'PENDING'"),
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requested_role: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("user_account.id", ondelete="SET NULL")
    )
    decision_note: Mapped[str | None] = mapped_column(String(1000))


class ApplicationSession(Base):
    __tablename__ = "application_session"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("user_account.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    reauthenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class AnalysisRun(Base):
    __tablename__ = "analysis_run"
    __table_args__ = (UniqueConstraint("fingerprint", "policy_context", name="uq_run_fingerprint_policy"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    policy_context: Mapped[str] = mapped_column(String(128), nullable=False)
    normalized_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="LOCAL_COMPLETE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now, onupdate=now)


class Scan(Base):
    __tablename__ = "scan"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("analysis_run.id"), nullable=False, index=True)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("user_account.id", ondelete="SET NULL"), index=True)
    guest_session_id: Mapped[str | None] = mapped_column(ForeignKey("application_session.id", ondelete="SET NULL"), index=True)
    original_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    display_url: Mapped[str] = mapped_column(String(512), nullable=False)
    requested_mode: Mapped[str] = mapped_column(String(24), nullable=False)
    enrichment_consent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notice_version: Mapped[str | None] = mapped_column(String(64))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now, index=True)


class SharedReport(Base):
    __tablename__ = "shared_report"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class ScanJob(Base):
    __tablename__ = "scan_job"
    __table_args__ = (
        UniqueConstraint("run_id", "kind", name="uq_job_run_kind"),
        Index("ix_job_lease", "state", "available_at", "lease_expires_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("analysis_run.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="ENRICH")
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="QUEUED")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now, onupdate=now)


class EvidenceObservation(Base):
    __tablename__ = "evidence_observation"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("analysis_run.id", ondelete="CASCADE"), nullable=False, index=True)
    family: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[str] = mapped_column(String(64), nullable=False, default="1")
    cached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sensitivity: Mapped[str] = mapped_column(String(32), nullable=False, default="INTERNAL")
    reason_code: Mapped[str | None] = mapped_column(String(64))


class Decision(Base):
    __tablename__ = "decision"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("analysis_run.id", ondelete="CASCADE"), nullable=False, index=True)
    supersedes_id: Mapped[str | None] = mapped_column(ForeignKey("decision.id"))
    stage: Mapped[str] = mapped_column(String(24), nullable=False)
    risk_band: Mapped[str] = mapped_column(String(24), nullable=False)
    analysis_scope: Mapped[str] = mapped_column(String(24), nullable=False)
    completion: Mapped[str] = mapped_column(String(24), nullable=False)
    engine_mode: Mapped[str] = mapped_column(String(24), nullable=False)
    probability: Mapped[float] = mapped_column(Float, nullable=False)
    model_probability: Mapped[float | None] = mapped_column(Float)
    rule_hits: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(128))
    fusion_version: Mapped[str] = mapped_column(String(64), nullable=False)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    counter_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    missing_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    safe_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now, index=True)


class Feedback(Base):
    __tablename__ = "feedback"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"), nullable=False, index=True)
    author_user_id: Mapped[str | None] = mapped_column(ForeignKey("user_account.id", ondelete="SET NULL"))
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    comment: Mapped[str | None] = mapped_column(String(1000))
    research_consent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="QUARANTINED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class ReviewCase(Base):
    __tablename__ = "review_case"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"), nullable=False, index=True)
    feedback_id: Mapped[str | None] = mapped_column(ForeignKey("feedback.id", ondelete="SET NULL"))
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="OPEN")
    claimed_by: Mapped[str | None] = mapped_column(ForeignKey("user_account.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now, onupdate=now)


class ReviewCaseEvent(Base):
    __tablename__ = "review_case_event"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("review_case.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_user_id: Mapped[str] = mapped_column(ForeignKey("user_account.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(24), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class DecisionPolicy(Base):
    __tablename__ = "decision_policy"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    version: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("user_account.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class ProviderConfig(Base):
    __tablename__ = "provider_config"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    updated_by: Mapped[str | None] = mapped_column(ForeignKey("user_account.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now, onupdate=now)


class ModelRelease(Base):
    __tablename__ = "model_release"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    version: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    artifact_uri: Mapped[str] = mapped_column(String(1000), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class DatasetSnapshot(Base):
    __tablename__ = "dataset_snapshot"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="FROZEN")
    created_by: Mapped[str] = mapped_column(ForeignKey("user_account.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class Experiment(Base):
    __tablename__ = "experiment"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("dataset_snapshot.id"), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="QUEUED")
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[str] = mapped_column(ForeignKey("user_account.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class ResearchExport(Base):
    __tablename__ = "research_export"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="QUEUED")
    filters: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    artifact_uri: Mapped[str | None] = mapped_column(String(1000))
    created_by: Mapped[str] = mapped_column(ForeignKey("user_account.id"), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class AuditEvent(Base):
    __tablename__ = "audit_event"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor_user_id: Mapped[str | None] = mapped_column(ForeignKey("user_account.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    previous_hmac: Mapped[str | None] = mapped_column(String(64))
    event_hmac: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_record"
    __table_args__ = (UniqueConstraint("principal", "operation", "key", name="uq_idempotency_scope"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    principal: Mapped[str] = mapped_column(String(128), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_bucket"
    __table_args__ = (UniqueConstraint("principal", "category", "window_start", name="uq_rate_limit_window"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    principal: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
