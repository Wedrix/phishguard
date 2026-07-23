from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, or_, select, update
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
    RoleRequestActionRequest,
    ReviewActionRequest,
    UserUpdateRequest,
)
from phishguard.application.audit import append_audit, verify_audit_chain
from phishguard.application.auth import Principal, require_fresh_auth, require_role
from phishguard.application.roles import (
    ROLE_REQUEST_STATES,
    RoleRequestError,
    RoleRequestService,
    role_request_payload,
)
from phishguard.application.scans import ScanService, scan_is_active
from phishguard.domain.types import Role
from phishguard.infrastructure.models import (
    ApplicationSession,
    AuditEvent,
    DatasetSnapshot,
    Decision,
    DecisionPolicy,
    EvidenceObservation,
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


def _role_request_api_error(exc: RoleRequestError) -> ApiError:
    status = 404 if exc.code == "role_request_not_found" else 409
    return ApiError(status, exc.code, str(exc))


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


@router.get("/review-cases/{case_id}/original-url")
def reveal_review_case_original_url(
    case_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
) -> dict[str, str]:
    _role(principal, Role.ANALYST, Role.ADMINISTRATOR)
    _fresh(db, principal)
    row = db.get(ReviewCase, case_id)
    scan = db.get(Scan, row.scan_id) if row else None
    if not row or not scan_is_active(scan):
        raise ApiError(404, "not_found", "Review case was not found")
    if row.claimed_by != principal.user_id:
        raise ApiError(409, "case_claim_required", "Claim this case before revealing the original URL")
    _audit(request, db, principal, "review.original_url.reveal", "review_case", row.id)
    service = ScanService(
        db,
        request.app.state.settings,
        request.app.state.cipher,
        request.app.state.model,
    )
    return {"url": service.reveal(scan)}


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
        if row.claimed_by != principal.user_id:
            raise ApiError(409, "case_claim_required", "Claim this case before adjudicating it")
        if not body.outcome:
            raise ApiError(422, "outcome_required", "An adjudication outcome is required")
        if not body.note or len(body.note.strip()) < 20:
            raise ApiError(422, "rationale_required", "A rationale of at least 20 characters is required")
        cited_ids = set(body.evidence_ids)
        if not cited_ids:
            raise ApiError(422, "evidence_citation_required", "Cite at least one evidence observation")
        reason_ids = {item for item in cited_ids if item.startswith("reason:")}
        observation_ids = cited_ids - reason_ids
        decision = db.scalar(
            select(Decision)
            .where(Decision.run_id == scan.run_id)
            .order_by(Decision.created_at.desc())
        )
        valid_reason_ids = {
            f"reason:{index}" for index in range(len(decision.reasons if decision else []))
        }
        if not reason_ids.issubset(valid_reason_ids):
            raise ApiError(422, "invalid_evidence_reference", "A cited reason does not belong to this case")
        available_citations = db.scalar(
            select(func.count())
            .select_from(EvidenceObservation)
            .where(
                EvidenceObservation.run_id == scan.run_id,
                EvidenceObservation.id.in_(observation_ids),
            )
        ) or 0
        if available_citations != len(observation_ids):
            raise ApiError(422, "invalid_evidence_reference", "A cited observation does not belong to this case")
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
        detail={"note": body.note, "outcome": body.outcome, "evidence_ids": body.evidence_ids},
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
    role_requests = RoleRequestService(db).repository
    return {
        "items": [
            {
                "id": user.id,
                "role": user.role,
                "is_canonical_admin": user.is_canonical_admin,
                "role_request": role_request_payload(role_requests.latest_for_user(user.id)),
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
    actor = db.get(UserAccount, principal.user_id)
    row = db.scalar(select(UserAccount).where(UserAccount.id == user_id).with_for_update())
    if not actor or not row:
        raise ApiError(404, "not_found", "User was not found")
    role = Role(body.role)
    changed = row.role != body.role or (row.disabled_at is not None) != body.disabled
    if changed and row.id == actor.id:
        raise ApiError(409, "self_role_change_forbidden", "Administrators cannot change their own account")
    if changed and row.is_canonical_admin:
        raise ApiError(
            409,
            "canonical_admin_protected",
            "The canonical administrator cannot be changed in the application",
        )
    if changed and row.role == Role.ADMINISTRATOR.value and not actor.is_canonical_admin:
        raise ApiError(
            403,
            "canonical_admin_required",
            "Only the canonical administrator may change another administrator",
        )
    if (
        role == Role.ADMINISTRATOR
        and row.role != Role.ADMINISTRATOR.value
        and not db.scalar(
            select(UserAccount.id).where(UserAccount.is_canonical_admin.is_(True))
        )
    ):
        raise ApiError(
            409,
            "canonical_admin_missing",
            "Bootstrap the canonical administrator before appointing other administrators",
        )
    if (
        role == Role.ADMINISTRATOR
        and row.role != Role.ADMINISTRATOR.value
        and (body.disabled or row.disabled_at)
    ):
        raise ApiError(
            409,
            "administrator_must_be_active",
            "Enable the account before assigning Administrator",
        )
    if (
        not body.disabled
        and role in {Role.ANALYST, Role.RESEARCHER, Role.ADMINISTRATOR}
        and not (
            row.email_verified and row.mfa_verified
        )
    ):
        raise ApiError(
            409,
            "privileged_assurance_required",
            "Verified email and TOTP are required before assigning a privileged role",
        )
    previous_role = row.role
    previously_disabled = row.disabled_at is not None
    changed_at = datetime.now(UTC)
    row.role = body.role
    if (row.disabled_at is not None) != body.disabled:
        row.disabled_at = changed_at if body.disabled else None
    if changed:
        RoleRequestService(db).revoke_sessions(row.id)
    resolved_request = RoleRequestService(db).approve_matching_pending(actor, row, body.role)
    _audit(
        request,
        db,
        principal,
        "user.update",
        "user_account",
        row.id,
        {
            "previous_role": previous_role,
            "role": body.role,
            "previously_disabled": previously_disabled,
            "disabled": body.disabled,
            "resolved_role_request_id": resolved_request.id if resolved_request else None,
        },
    )
    payload = {
        "id": row.id,
        "role": row.role,
        "is_canonical_admin": row.is_canonical_admin,
        "disabled": row.disabled_at is not None,
        "role_request": role_request_payload(
            resolved_request or RoleRequestService(db).repository.latest_for_user(row.id)
        ),
    }
    _remember(db, principal.key, operation, key, 200, payload)
    return payload


@router.post("/admin/users/{user_id}/revoke-sessions")
def revoke_user_sessions(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    _fresh(db, principal)
    operation = f"admin:user:{user_id}:revoke_sessions"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    actor = db.get(UserAccount, principal.user_id)
    row = db.scalar(select(UserAccount).where(UserAccount.id == user_id).with_for_update())
    if not actor or not row:
        raise ApiError(404, "not_found", "User was not found")
    if row.is_canonical_admin:
        raise ApiError(409, "canonical_admin_protected", "The canonical administrator is protected")
    if row.role == Role.ADMINISTRATOR.value and not actor.is_canonical_admin:
        raise ApiError(403, "canonical_admin_required", "Only the canonical administrator may revoke another administrator")
    changed_at = datetime.now(UTC)
    result = db.execute(
        update(ApplicationSession)
        .where(
            ApplicationSession.user_id == user_id,
            ApplicationSession.revoked_at.is_(None),
        )
        .values(revoked_at=changed_at)
    )
    count = result.rowcount or 0
    payload = {"user_id": user_id, "revoked_session_count": count}
    _audit(request, db, principal, "user.sessions.revoke", "user_account", user_id, {"count": count})
    _remember(db, principal.key, operation, key, 200, payload)
    return payload


@router.get("/admin/role-requests")
def admin_role_requests(
    state: str | None = "PENDING",
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    normalized = state.upper() if state else None
    if normalized and normalized not in ROLE_REQUEST_STATES:
        raise ApiError(422, "invalid_role_request_state", "Role request state is invalid")
    return {
        "items": [
            role_request_payload(row)
            for row in RoleRequestService(db).repository.list(normalized)
        ]
    }


@router.post("/admin/role-requests/{role_request_id}/actions")
def decide_role_request(
    role_request_id: str,
    body: RoleRequestActionRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    _fresh(db, principal)
    operation = f"admin:role_request:{role_request_id}"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    actor = db.get(UserAccount, principal.user_id)
    if not actor:
        raise ApiError(404, "not_found", "Administrator was not found")
    try:
        row, target, role_changed = RoleRequestService(db).decide(
            actor,
            role_request_id,
            body.action,
            body.note,
        )
    except RoleRequestError as exc:
        raise _role_request_api_error(exc) from exc
    payload = role_request_payload(row)
    assert payload is not None
    _audit(
        request,
        db,
        principal,
        f"role_request.{body.action.lower()}",
        "role_request",
        row.id,
        {
            "target_user_id": target.id,
            "requested_role": row.requested_role,
            "role_changed": role_changed,
        },
    )
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


@router.post("/admin/decision-policies/{policy_id}/activate")
def activate_policy(
    policy_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    _fresh(db, principal)
    operation = f"admin:policy:approve:{policy_id}"
    if replay := _replay(db, principal.key, operation, key):
        return replay.response
    row = db.scalar(select(DecisionPolicy).where(DecisionPolicy.id == policy_id).with_for_update())
    if not row:
        raise ApiError(404, "not_found", "Decision policy was not found")
    previous = db.scalar(select(DecisionPolicy).where(DecisionPolicy.active.is_(True)))
    db.execute(update(DecisionPolicy).values(active=False))
    row.active = True
    payload = {
        **_policy(row),
        "deployment_required": True,
        "previous_policy_id": previous.id if previous and previous.id != row.id else None,
    }
    _audit(
        request,
        db,
        principal,
        "policy.approve_for_deployment",
        "decision_policy",
        row.id,
        {"previous_policy_id": payload["previous_policy_id"]},
    )
    _remember(db, principal.key, operation, key, 200, payload)
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
    required_gates = ("data", "feature", "evaluation", "security")
    gates = row.metrics.get("gates") if isinstance(row.metrics, dict) else None
    failed_gates = [gate for gate in required_gates if not isinstance(gates, dict) or gates.get(gate) is not True]
    if failed_gates:
        raise ApiError(
            409,
            "model_gates_failed",
            "All model governance gates must pass before deployment approval",
            {"failed_gates": failed_gates},
        )
    # Registry approval is deliberately distinct from runtime activation. The
    # checksum-pinned demo-model overlay performs the controlled rollout.
    previous = db.scalar(select(ModelRelease).where(ModelRelease.active.is_(True)))
    db.execute(update(ModelRelease).values(active=False))
    row.active = True
    _audit(
        request,
        db,
        principal,
        "model.approve_for_deployment",
        "model_release",
        row.id,
        {"previous_model_id": previous.id if previous and previous.id != row.id else None},
    )
    payload = {
        **_model(row),
        "runtime_active": False,
        "deployment_required": True,
        "previous_model_id": previous.id if previous and previous.id != row.id else None,
        "next_step": "Deploy the checksum-pinned demo-model overlay and verify the rollout.",
    }
    _remember(db, principal.key, operation, key, 200, payload)
    return payload


@router.get("/admin/audit-events")
def audit_events(
    q: str | None = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    if q and len(q) > 100:
        raise ApiError(422, "search_too_long", "Audit search is limited to 100 characters")
    statement = select(AuditEvent)
    if q:
        term = f"%{q.strip()}%"
        statement = statement.where(
            or_(
                AuditEvent.action.ilike(term),
                AuditEvent.object_type.ilike(term),
                AuditEvent.object_id.ilike(term),
                AuditEvent.correlation_id.ilike(term),
                AuditEvent.outcome.ilike(term),
            )
        )
    rows = db.scalars(statement.order_by(AuditEvent.created_at.desc()).limit(200))
    return {
        "items": [
            {
                "id": row.id,
                "action": row.action,
                "object_type": row.object_type,
                "object_id": row.object_id,
                "outcome": row.outcome,
                "correlation_id": row.correlation_id,
                "previous_hmac": row.previous_hmac,
                "event_hmac": row.event_hmac,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
    }


@router.get("/admin/audit-events/verify")
def verify_audit_events(
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    rows = list(db.scalars(select(AuditEvent).order_by(AuditEvent.created_at, AuditEvent.id)))
    valid, failed_event_id = verify_audit_chain(
        rows,
        request.app.state.settings.phishguard_hmac_key.encode(),
    )
    return {
        "valid": valid,
        "checked_events": len(rows),
        "failed_event_id": failed_event_id,
        "head_hmac": rows[-1].event_hmac if rows else None,
        "verified_at": datetime.now(UTC).isoformat(),
    }


@router.get("/admin/health")
def admin_health(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _role(principal, Role.ADMINISTRATOR)
    queue = dict(db.execute(select(ScanJob.state, func.count()).group_by(ScanJob.state)).all())
    canonical_count = db.scalar(
        select(func.count())
        .select_from(UserAccount)
        .where(UserAccount.is_canonical_admin.is_(True))
    ) or 0
    since = datetime.now(UTC) - timedelta(days=7)
    decisions = list(
        db.scalars(
            select(Decision)
            .where(Decision.created_at >= since)
            .order_by(Decision.created_at.desc())
            .limit(5000)
        )
    )
    latest_decisions: dict[str, Decision] = {}
    for decision in decisions:
        latest_decisions.setdefault(decision.run_id, decision)
    outcomes: dict[str, int] = {}
    models: dict[str, int] = {}
    for decision in latest_decisions.values():
        outcomes[decision.risk_band] = outcomes.get(decision.risk_band, 0) + 1
        model = decision.model_version or "rule-only"
        models[model] = models.get(model, 0) + 1
    provider_rows = list(
        db.scalars(
            select(EvidenceObservation)
            .where(
                EvidenceObservation.source == "google_web_risk",
                EvidenceObservation.retrieved_at >= since,
            )
            .order_by(EvidenceObservation.retrieved_at.desc())
            .limit(5000)
        )
    )
    provider_states: dict[str, int] = {}
    for observation in provider_rows:
        provider_states[observation.state] = provider_states.get(observation.state, 0) + 1
    active_sessions = db.scalar(
        select(func.count())
        .select_from(ApplicationSession)
        .where(
            ApplicationSession.user_id.is_not(None),
            ApplicationSession.revoked_at.is_(None),
            ApplicationSession.expires_at > datetime.now(UTC),
        )
    ) or 0
    return {
        "database": "available",
        "jobs": queue,
        "active_user_sessions": active_sessions,
        "decisions_7d": len(latest_decisions),
        "outcomes_7d": outcomes,
        "model_versions_7d": models,
        "provider_telemetry": {
            "google_web_risk": {
                "observations_7d": len(provider_rows),
                "states": provider_states,
                "last_retrieved_at": provider_rows[0].retrieved_at.isoformat() if provider_rows else None,
            }
        },
        "canonical_admin": {
            "status": "CONFIGURED" if canonical_count == 1 else "MISSING",
            "count": canonical_count,
        },
        "checked_at": datetime.now(UTC).isoformat(),
    }


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
            "research_consent": feedback.research_consent,
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
