from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from phishguard.api.dependencies import csrf_guard, get_db, idempotency_key, require_principal
from phishguard.api.errors import ApiError
from phishguard.api.schemas import (
    DatasetCreateRequest,
    ExperimentCreateRequest,
    ExportCreateRequest,
    ModelCreateRequest,
    PolicyCreateRequest,
    ProviderUpdateRequest,
    ReviewActionRequest,
    UserUpdateRequest,
)
from phishguard.application.audit import append_audit
from phishguard.application.auth import Principal, require_fresh_auth, require_role
from phishguard.application.scans import scan_is_active
from phishguard.domain.types import Role
from phishguard.infrastructure.models import (
    ApplicationSession,
    AuditEvent,
    DatasetSnapshot,
    DecisionPolicy,
    Experiment,
    Feedback,
    IdempotencyRecord,
    ModelRelease,
    ProviderConfig,
    ResearchExport,
    ReviewCase,
    ReviewCaseEvent,
    Scan,
    ScanJob,
    UserAccount,
)

router = APIRouter(prefix="/api/v1")


def _role(principal: Principal, *roles: Role) -> Principal:
    try:
        return require_role(principal, *roles)
    except PermissionError as exc:
        raise ApiError(403, "forbidden", "Insufficient permissions") from exc


def _fresh(db: Session, principal: Principal) -> None:
    try:
        require_fresh_auth(db, principal)
    except PermissionError as exc:
        raise ApiError(403, "fresh_auth_required", "Authentication within the last five minutes is required") from exc


def _audit(
    request: Request,
    db: Session,
    principal: Principal,
    action: str,
    object_type: str,
    object_id: str | None,
    detail: dict[str, object] | None = None,
) -> None:
    append_audit(
        db,
        request.app.state.settings.phishguard_hmac_key.encode(),
        principal.user_id,
        action,
        object_type,
        object_id,
        "SUCCESS",
        request.state.correlation_id,
        detail,
    )


@router.get("/review-cases")
def list_review_cases(
    db: Session = Depends(get_db), principal: Principal = Depends(require_principal)
) -> dict[str, Any]:
    _role(principal, Role.ANALYST, Role.ADMINISTRATOR)
    rows = db.scalars(
        select(ReviewCase)
        .join(Scan, Scan.id == ReviewCase.scan_id)
        .where(Scan.deleted_at.is_(None), Scan.expires_at > datetime.now(UTC))
        .order_by(ReviewCase.updated_at.desc())
        .limit(100)
    )
    return {"items": [_case(row) for row in rows]}


@router.get("/review-cases/{case_id}")
def get_review_case(
    case_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)
) -> dict[str, Any]:
    _role(principal, Role.ANALYST, Role.ADMINISTRATOR)
    row = db.get(ReviewCase, case_id)
    scan = db.get(Scan, row.scan_id) if row else None
    if not row or not scan_is_active(scan):
        raise ApiError(404, "not_found", "Review case was not found")
    events = db.scalars(select(ReviewCaseEvent).where(ReviewCaseEvent.case_id == row.id).order_by(ReviewCaseEvent.created_at))
    feedback = db.get(Feedback, row.feedback_id) if row.feedback_id else None
    return {**_case(row, feedback), "events": [_case_event(event) for event in events]}


@router.post("/review-cases/{case_id}/actions")
def review_action(
    case_id: str,
    body: ReviewActionRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.ANALYST, Role.ADMINISTRATOR)
    replay = _replay(db, principal.key, f"review:{case_id}", key)
    if replay:
        return replay.response
    row = db.scalar(select(ReviewCase).where(ReviewCase.id == case_id).with_for_update())
    scan = db.get(Scan, row.scan_id) if row else None
    if not row or not scan_is_active(scan):
        raise ApiError(404, "not_found", "Review case was not found")
    if row.state == "ADJUDICATED":
        raise ApiError(409, "case_closed", "An adjudicated review case cannot be changed")
    if body.action == "claim":
        if row.claimed_by and row.claimed_by != principal.user_id:
            raise ApiError(409, "already_claimed", "Review case is already claimed")
        row.claimed_by, row.state = principal.user_id, "CLAIMED"
    elif body.action == "release":
        if row.claimed_by != principal.user_id and principal.role != Role.ADMINISTRATOR:
            raise ApiError(409, "not_claimant", "Only the claimant may release this case")
        row.claimed_by, row.state = None, "OPEN"
    elif body.action == "annotate":
        if not body.note:
            raise ApiError(422, "note_required", "An annotation note is required")
    elif body.action == "adjudicate":
        if row.claimed_by not in {None, principal.user_id} and principal.role != Role.ADMINISTRATOR:
            raise ApiError(409, "not_claimant", "Only the claimant may adjudicate this case")
        if not body.outcome:
            raise ApiError(422, "outcome_required", "An adjudication outcome is required")
        row.state = "ADJUDICATED"
        if row.feedback_id:
            feedback = db.get(Feedback, row.feedback_id)
            if feedback:
                feedback.status = f"REVIEWED_{body.outcome}"
    assert principal.user_id is not None
    event = ReviewCaseEvent(
        case_id=row.id,
        actor_user_id=principal.user_id,
        action=body.action.upper(),
        detail={"note": body.note, "outcome": body.outcome},
    )
    db.add(event)
    db.flush()
    payload = _case(row)
    _remember(db, principal.key, f"review:{case_id}", key, 200, payload)
    _audit(request, db, principal, f"review.{body.action}", "review_case", row.id, {"outcome": body.outcome})
    return payload


@router.get("/admin/users")
def admin_users(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    users = db.scalars(select(UserAccount).order_by(UserAccount.created_at.desc()).limit(100))
    return {
        "items": [
            {
                "id": user.id,
                "role": user.role,
                "email_verified": user.email_verified,
                "mfa_verified": user.mfa_verified,
                "disabled": user.disabled_at is not None,
                "created_at": user.created_at.isoformat(),
            }
            for user in users
        ]
    }


@router.put("/admin/users/{user_id}")
def update_user(
    user_id: str,
    body: UserUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    _fresh(db, principal)
    operation = f"admin:user:{user_id}"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    row = db.get(UserAccount, user_id)
    if not row or row.role == Role.ADMINISTRATOR.value or row.id == principal.user_id:
        raise ApiError(404, "not_found", "User was not found")
    role = Role(body.role)
    if role in {Role.ANALYST, Role.RESEARCHER} and not (row.email_verified and row.mfa_verified):
        raise ApiError(
            409,
            "privileged_assurance_required",
            "Verified email and TOTP are required before assigning a privileged role",
        )
    changed = row.role != body.role or (row.disabled_at is not None) != body.disabled
    changed_at = datetime.now(UTC)
    row.role = body.role
    if (row.disabled_at is not None) != body.disabled:
        row.disabled_at = changed_at if body.disabled else None
    if changed:
        db.execute(
            update(ApplicationSession)
            .where(
                ApplicationSession.user_id == row.id,
                ApplicationSession.revoked_at.is_(None),
            )
            .values(revoked_at=changed_at)
        )
    _audit(request, db, principal, "user.update", "user_account", row.id, {"role": body.role, "disabled": body.disabled})
    payload = {"id": row.id, "role": row.role, "disabled": row.disabled_at is not None}
    _remember(db, principal.key, operation, key, 200, payload)
    return payload


@router.get("/admin/providers")
def admin_providers(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    rows = db.scalars(select(ProviderConfig).order_by(ProviderConfig.provider))
    return {"items": [_provider(row) for row in rows]}


@router.put("/admin/providers/{provider}")
def update_provider(
    provider: str,
    body: ProviderUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    _fresh(db, principal)
    if provider != "google_web_risk":
        raise ApiError(404, "not_found", "Provider was not found")
    operation = f"admin:provider:{provider}"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    row = db.scalar(select(ProviderConfig).where(ProviderConfig.provider == provider))
    if not row:
        row = ProviderConfig(provider=provider)
        db.add(row)
    row.enabled, row.config, row.updated_by = body.enabled, body.config, principal.user_id
    db.flush()
    _audit(request, db, principal, "provider.update", "provider", provider, {"enabled": body.enabled})
    payload = _provider(row)
    _remember(db, principal.key, operation, key, 200, payload)
    return payload


@router.get("/admin/decision-policies")
def admin_policies(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    rows = db.scalars(select(DecisionPolicy).order_by(DecisionPolicy.created_at.desc()))
    return {"items": [_policy(row) for row in rows]}


@router.post("/admin/decision-policies", status_code=201)
def create_policy(
    body: PolicyCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    _fresh(db, principal)
    operation = "admin:policy:create"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    row = DecisionPolicy(version=body.version, config=body.config, created_by=principal.user_id)
    db.add(row)
    db.flush()
    _audit(request, db, principal, "policy.create", "decision_policy", row.id)
    payload = _policy(row)
    _remember(db, principal.key, operation, key, 201, payload)
    return payload


@router.get("/admin/models")
def admin_models(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    rows = db.scalars(select(ModelRelease).order_by(ModelRelease.created_at.desc()))
    return {"items": [_model(row) for row in rows]}


@router.post("/admin/models", status_code=201)
def register_model(
    body: ModelCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    _fresh(db, principal)
    operation = "admin:model:register"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    row = ModelRelease(**body.model_dump())
    db.add(row)
    db.flush()
    _audit(request, db, principal, "model.register", "model_release", row.id)
    payload = _model(row)
    _remember(db, principal.key, operation, key, 201, payload)
    return payload


@router.post("/admin/models/{model_id}/activate")
def activate_model(
    model_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    _fresh(db, principal)
    operation = f"admin:model:approve:{model_id}"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    row = db.get(ModelRelease, model_id)
    if not row:
        raise ApiError(404, "not_found", "Model was not found")
    # Registry approval is deliberately distinct from runtime activation. The
    # checksum-pinned demo-model overlay performs the controlled rollout.
    db.execute(update(ModelRelease).values(active=False))
    row.active = True
    _audit(request, db, principal, "model.approve_for_deployment", "model_release", row.id)
    payload = {
        **_model(row),
        "runtime_active": False,
        "deployment_required": True,
        "next_step": "Deploy the checksum-pinned demo-model overlay and verify the rollout.",
    }
    _remember(db, principal.key, operation, key, 200, payload)
    return payload


@router.get("/admin/audit-events")
def audit_events(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    rows = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(200))
    return {
        "items": [
            {
                "id": row.id,
                "action": row.action,
                "object_type": row.object_type,
                "object_id": row.object_id,
                "outcome": row.outcome,
                "correlation_id": row.correlation_id,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
    }


@router.get("/admin/health")
def admin_health(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    queue = dict(db.execute(select(ScanJob.state, func.count()).group_by(ScanJob.state)).all())
    return {"database": "available", "jobs": queue, "checked_at": datetime.now(UTC).isoformat()}


@router.get("/research/datasets")
def datasets(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _role(principal, Role.RESEARCHER, Role.ADMINISTRATOR)
    return {"items": [_dataset(row) for row in db.scalars(select(DatasetSnapshot).order_by(DatasetSnapshot.created_at.desc()))]}


@router.post("/research/datasets", status_code=201)
def create_dataset(
    body: DatasetCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.RESEARCHER, Role.ADMINISTRATOR)
    operation = "research:dataset:create"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    assert principal.user_id
    row = DatasetSnapshot(**body.model_dump(), created_by=principal.user_id)
    db.add(row)
    db.flush()
    payload = _dataset(row)
    _audit(request, db, principal, "research.dataset.create", "dataset_snapshot", row.id)
    _remember(db, principal.key, operation, key, 201, payload)
    return payload


@router.get("/research/experiments")
def experiments(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _role(principal, Role.RESEARCHER, Role.ADMINISTRATOR)
    rows = db.scalars(select(Experiment).order_by(Experiment.created_at.desc()))
    return {"items": [_experiment(row) for row in rows]}


@router.post("/research/experiments", status_code=202)
def create_experiment(
    body: ExperimentCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.RESEARCHER, Role.ADMINISTRATOR)
    operation = "research:experiment:create"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    assert principal.user_id
    if not db.get(DatasetSnapshot, body.dataset_id):
        raise ApiError(404, "not_found", "Dataset was not found")
    row = Experiment(**body.model_dump(), created_by=principal.user_id)
    db.add(row)
    db.flush()
    payload = _experiment(row)
    _audit(request, db, principal, "research.experiment.create", "experiment", row.id)
    _remember(db, principal.key, operation, key, 202, payload)
    return payload


@router.get("/research/exports")
def exports(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _role(principal, Role.RESEARCHER, Role.ADMINISTRATOR)
    rows = db.scalars(select(ResearchExport).order_by(ResearchExport.created_at.desc()))
    return {"items": [_export(row) for row in rows]}


@router.post("/research/exports", status_code=202)
def create_export(
    body: ExportCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.RESEARCHER, Role.ADMINISTRATOR)
    _fresh(db, principal)
    operation = "research:export:create"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    assert principal.user_id
    row = ResearchExport(
        filters=body.filters,
        created_by=principal.user_id,
        expires_at=datetime.now(UTC) + timedelta(hours=24),
    )
    db.add(row)
    db.flush()
    payload = _export(row)
    _audit(request, db, principal, "research.export.create", "research_export", row.id)
    _remember(db, principal.key, operation, key, 202, payload)
    return payload


def _case(row: ReviewCase, feedback: Feedback | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": row.id,
        "scan_id": row.scan_id,
        "feedback_id": row.feedback_id,
        "state": row.state,
        "claimed_by": row.claimed_by,
        "updated_at": row.updated_at.isoformat(),
    }
    if feedback:
        payload["feedback"] = {
            "id": feedback.id,
            "category": feedback.category,
            "comment": feedback.comment,
            "status": feedback.status,
            "created_at": feedback.created_at.isoformat(),
        }
    return payload


def _case_event(row: ReviewCaseEvent) -> dict[str, Any]:
    return {"id": row.id, "action": row.action, "detail": row.detail, "created_at": row.created_at.isoformat()}


def _provider(row: ProviderConfig) -> dict[str, Any]:
    return {"id": row.id, "provider": row.provider, "enabled": row.enabled, "config": row.config, "updated_at": row.updated_at.isoformat()}


def _policy(row: DecisionPolicy) -> dict[str, Any]:
    return {"id": row.id, "version": row.version, "config": row.config, "active": row.active, "created_at": row.created_at.isoformat()}


def _model(row: ModelRelease) -> dict[str, Any]:
    return {
        "id": row.id,
        "version": row.version,
        "artifact_uri": row.artifact_uri,
        "sha256": row.sha256,
        "metrics": row.metrics,
        "approved_for_deployment": row.active,
        "runtime_active": False,
    }


def _dataset(row: DatasetSnapshot) -> dict[str, Any]:
    return {"id": row.id, "name": row.name, "sha256": row.sha256, "manifest": row.manifest, "state": row.state, "created_at": row.created_at.isoformat()}


def _experiment(row: Experiment) -> dict[str, Any]:
    return {"id": row.id, "dataset_id": row.dataset_id, "state": row.state, "config": row.config, "result": row.result, "created_at": row.created_at.isoformat()}


def _export(row: ResearchExport) -> dict[str, Any]:
    return {"id": row.id, "state": row.state, "filters": row.filters, "artifact_uri": row.artifact_uri, "expires_at": row.expires_at.isoformat() if row.expires_at else None}


def _replay(db: Session, principal: str, operation: str, key: str) -> IdempotencyRecord | None:
    row = db.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.principal == principal,
            IdempotencyRecord.operation == operation,
            IdempotencyRecord.key == key,
        )
    )
    if row:
        expiry = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
        if expiry <= datetime.now(UTC):
            db.delete(row)
            db.flush()
            return None
    return row


def _remember(db: Session, principal: str, operation: str, key: str, status: int, payload: dict[str, Any]) -> None:
    db.add(
        IdempotencyRecord(
            principal=principal,
            operation=operation,
            key=key,
            status_code=status,
            response=payload,
            expires_at=datetime.now(UTC) + timedelta(hours=24),
        )
    )
