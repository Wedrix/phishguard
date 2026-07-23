from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session

from phishguard.api.dependencies import (
    CSRF_COOKIE,
    csrf_guard,
    get_db,
    get_principal,
    idempotency_key,
    require_principal,
    session_cookie_name,
)
from phishguard.api.errors import ApiError
from phishguard.api.schemas import (
    FeedbackRequest,
    RetentionUpdateRequest,
    RoleRequestCreateRequest,
    SessionRequest,
    ShareRequest,
    ScanRequest,
)
from phishguard.application.auth import (
    Principal,
    adopt_guest_scans,
    create_guest_session,
    create_user_session,
    token_digest,
    verify_csrf,
    verify_identity_token,
    require_fresh_auth,
)
from phishguard.application.audit import append_audit
from phishguard.application.roles import (
    RoleRequestError,
    RoleRequestService,
    role_request_payload,
)
from phishguard.application.scans import ScanService, scan_is_active
from phishguard.domain.types import Role
from phishguard.domain.url_policy import UrlPolicyError
from phishguard.infrastructure.models import (
    AnalysisRun,
    ApplicationSession,
    Decision,
    EvidenceObservation,
    Feedback,
    IdempotencyRecord,
    RateLimitBucket,
    ReviewCase,
    Scan,
    SharedReport,
    UserAccount,
)

router = APIRouter(prefix="/api/v1")

DEFAULT_ROUTES = {
    Role.REGISTERED_USER.value: "/history",
    Role.ANALYST.value: "/analyst/cases",
    Role.ADMINISTRATOR.value: "/admin",
    Role.RESEARCHER.value: "/research",
}


def _service(request: Request, db: Session) -> ScanService:
    return ScanService(db, request.app.state.settings, request.app.state.cipher, request.app.state.model)


def _fresh_account_user(db: Session, principal: Principal) -> UserAccount:
    if not principal.user_id:
        raise ApiError(401, "authentication_required", "A registered account is required")
    try:
        require_fresh_auth(db, principal)
    except PermissionError as exc:
        raise ApiError(
            403,
            "fresh_auth_required",
            "Authentication within the last five minutes is required",
        ) from exc
    user = db.get(UserAccount, principal.user_id)
    if not user:
        raise ApiError(401, "authentication_required", "A registered account is required")
    return user


def _account_user(db: Session, principal: Principal) -> UserAccount:
    if not principal.user_id:
        raise ApiError(401, "authentication_required", "A registered account is required")
    user = db.get(UserAccount, principal.user_id)
    if not user:
        raise ApiError(401, "authentication_required", "A registered account is required")
    return user


def _role_request_api_error(exc: RoleRequestError) -> ApiError:
    status = 404 if exc.code == "role_request_not_found" else 409
    return ApiError(status, exc.code, str(exc))


def _session_payload(
    request: Request,
    db: Session,
    principal: Principal | None,
) -> dict[str, Any]:
    maximum_retention = request.app.state.settings.scan_retention_days
    user = db.get(UserAccount, principal.user_id) if principal and principal.user_id else None
    if not user:
        return {
            "authenticated": False,
            "session_kind": "GUEST" if principal else "ANONYMOUS",
            "user_id": None,
            "role": None,
            "is_canonical_admin": False,
            "role_request": None,
            "scan_retention_days": None,
            "scan_retention_max_days": maximum_retention,
            "default_route": "/",
        }
    return {
        "authenticated": True,
        "session_kind": "USER",
        "user_id": user.id,
        "role": user.role,
        "is_canonical_admin": user.is_canonical_admin,
        "role_request": role_request_payload(
            RoleRequestService(db).repository.latest_for_user(user.id)
        ),
        "scan_retention_days": min(
            user.scan_retention_days or maximum_retention,
            maximum_retention,
        ),
        "scan_retention_max_days": maximum_retention,
        "default_route": DEFAULT_ROUTES[user.role],
    }


def _set_session_cookies(response: Response, request: Request, token: str, csrf: str, max_age: int) -> None:
    secure = request.app.state.settings.cookie_secure
    response.set_cookie(
        session_cookie_name(request),
        token,
        max_age=max_age,
        secure=secure,
        httponly=True,
        samesite="lax",
        path="/",
    )
    response.set_cookie(CSRF_COOKIE, csrf, max_age=max_age, secure=secure, httponly=False, samesite="lax", path="/")


def _clear_session_cookies(response: Response, request: Request) -> None:
    secure = request.app.state.settings.cookie_secure
    response.delete_cookie(session_cookie_name(request), path="/", secure=secure, httponly=True, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, httponly=False, samesite="lax")


@router.post("/session")
def exchange_session(
    body: SessionRequest,
    request: Request,
    db: Session = Depends(get_db),
    previous_principal: Principal | None = Depends(get_principal),
) -> JSONResponse:
    settings = request.app.state.settings
    claims = verify_identity_token(body.id_token, settings.identity_project_id, settings.dev_auth_enabled)
    principal, token, csrf = create_user_session(db, claims, settings.phishguard_hmac_key.encode())
    assert principal.user_id is not None
    user = db.get(UserAccount, principal.user_id)
    assert user is not None
    role_service = RoleRequestService(db)
    role_request = role_service.repository.latest_for_user(user.id)
    if body.requested_role in {"ANALYST", "RESEARCHER"}:
        try:
            role_request, created = role_service.request(user, body.requested_role)
        except RoleRequestError:
            # A role preference must never make an otherwise valid sign-in fail.
            role_request = role_service.repository.latest_for_user(user.id)
        else:
            if created:
                append_audit(
                    db,
                    settings.phishguard_hmac_key.encode(),
                    user.id,
                    "role_request.create",
                    "role_request",
                    role_request.id,
                    "SUCCESS",
                    request.state.correlation_id,
                    {"requested_role": role_request.requested_role, "source": "session"},
                )
    adopted_scan_count = 0
    if previous_principal and not previous_principal.user_id:
        retention_days = min(
            user.scan_retention_days or settings.scan_retention_days,
            settings.scan_retention_days,
        )
        adopted_scan_count = adopt_guest_scans(
            db,
            previous_principal.session_id,
            user.id,
            retention_days,
        )
        if adopted_scan_count:
            append_audit(
                db,
                settings.phishguard_hmac_key.encode(),
                user.id,
                "scan.guest_adopt",
                "user_account",
                user.id,
                "SUCCESS",
                request.state.correlation_id,
                {"scan_count": adopted_scan_count},
            )
    payload = _session_payload(request, db, principal)
    payload.update({"adopted_scan_count": adopted_scan_count, "csrf_token": csrf})
    response = JSONResponse(payload, status_code=201)
    _set_session_cookies(response, request, token, csrf, 8 * 60 * 60)
    return response


@router.post("/session/reauth")
def reauthenticate(
    body: SessionRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
) -> dict[str, str]:
    if not principal.user_id:
        raise ApiError(401, "authentication_required", "A registered account is required")
    settings = request.app.state.settings
    claims = verify_identity_token(body.id_token, settings.identity_project_id, settings.dev_auth_enabled)
    user = db.get(UserAccount, principal.user_id)
    if not user or claims.subject != user.identity_subject:
        raise ApiError(401, "identity_mismatch", "The identity does not match this session")
    if principal.role and principal.role.value in {"ANALYST", "ADMINISTRATOR", "RESEARCHER"} and not claims.mfa_verified:
        raise ApiError(401, "mfa_required", "Multi-factor authentication is required")
    if claims.authenticated_at < datetime.now(UTC) - timedelta(minutes=5):
        raise ApiError(401, "fresh_auth_required", "Identity Platform authentication is older than five minutes")
    row = db.get(ApplicationSession, principal.session_id)
    assert row is not None
    # Preserve the actual Identity Platform authentication time. Replacing it
    # with request time could extend a nearly-five-minute-old credential into
    # an unintended second five-minute window.
    row.reauthenticated_at = claims.authenticated_at
    return {"status": "reauthenticated"}


@router.delete("/session", status_code=204, response_class=Response, response_model=None)
def end_session(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
) -> None:
    row = db.get(ApplicationSession, principal.session_id)
    if row:
        row.revoked_at = datetime.now(UTC)
    _clear_session_cookies(response, request)


@router.get("/me")
def me(
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal | None = Depends(get_principal),
) -> dict[str, Any]:
    return _session_payload(request, db, principal)


@router.post("/account/role-requests")
def create_role_request(
    body: RoleRequestCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> JSONResponse:
    user = _account_user(db, principal)
    operation = "account_role_request_create"
    if replay := _idempotent_replay(db, principal.key, operation, key):
        return JSONResponse(replay.response, status_code=replay.status_code)
    try:
        row, created = RoleRequestService(db).request(user, body.requested_role)
    except RoleRequestError as exc:
        raise _role_request_api_error(exc) from exc
    status = 201 if created else 200
    payload = role_request_payload(row)
    assert payload is not None
    if created:
        append_audit(
            db,
            request.app.state.settings.phishguard_hmac_key.encode(),
            user.id,
            "role_request.create",
            "role_request",
            row.id,
            "SUCCESS",
            request.state.correlation_id,
            {"requested_role": row.requested_role, "source": "account"},
        )
    _store_idempotency(db, principal.key, operation, key, status, payload)
    return JSONResponse(payload, status_code=status)


@router.delete(
    "/account/role-requests/{role_request_id}",
    status_code=204,
    response_class=Response,
    response_model=None,
)
def cancel_role_request(
    role_request_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> Response:
    user = _account_user(db, principal)
    operation = f"account_role_request_cancel:{role_request_id}"
    if replay := _idempotent_replay(db, principal.key, operation, key):
        return Response(status_code=replay.status_code)
    try:
        row = RoleRequestService(db).cancel(user, role_request_id)
    except RoleRequestError as exc:
        raise _role_request_api_error(exc) from exc
    append_audit(
        db,
        request.app.state.settings.phishguard_hmac_key.encode(),
        user.id,
        "role_request.cancel",
        "role_request",
        row.id,
        "SUCCESS",
        request.state.correlation_id,
        {"requested_role": row.requested_role},
    )
    _store_idempotency(db, principal.key, operation, key, 204, {})
    return Response(status_code=204)


@router.post("/account/export")
def export_account_data(
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
) -> JSONResponse:
    user = _fresh_account_user(db, principal)
    service = _service(request, db)
    scans = list(
        db.scalars(
            select(Scan)
            .where(
                Scan.owner_user_id == user.id,
                Scan.deleted_at.is_(None),
                Scan.expires_at > datetime.now(UTC),
            )
            .order_by(Scan.created_at.desc())
        )
    )
    items = []
    for scan in scans:
        decision = service.decision_for_scan(scan)
        item = _scan_payload(scan, decision, _scan_status(db, scan))
        item["decision"] = {
            "id": decision.id,
            "recorded_at": decision.created_at.isoformat(),
            **item["decision"],
        }
        items.append(item)
    generated_at = datetime.now(UTC)
    append_audit(
        db,
        request.app.state.settings.phishguard_hmac_key.encode(),
        user.id,
        "account.data.export",
        "user_account",
        user.id,
        "SUCCESS",
        request.state.correlation_id,
        {"scan_count": len(items)},
    )
    return JSONResponse(
        {
            "schema_version": "phishguard-account-export/1",
            "generated_at": generated_at.isoformat(),
            "user_id": user.id,
            "scans": items,
            "identity_platform_identity_included": False,
        },
        headers={"Content-Disposition": 'attachment; filename="phishguard-account-export.json"'},
    )


@router.put("/account/retention")
def update_account_retention(
    body: RetentionUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    user = _fresh_account_user(db, principal)
    operation = "account_retention"
    replay = _idempotent_replay(db, principal.key, operation, key)
    if replay:
        return replay.response
    maximum = request.app.state.settings.scan_retention_days
    if body.days > maximum:
        raise ApiError(
            422,
            "retention_exceeds_policy",
            f"Retention cannot exceed the {maximum}-day application policy",
            {"days": f"Choose a value from 1 to {maximum}"},
        )
    user.scan_retention_days = body.days
    payload = {"scan_retention_days": body.days, "applies_to": "new_scans"}
    _store_idempotency(db, principal.key, operation, key, 200, payload)
    append_audit(
        db,
        request.app.state.settings.phishguard_hmac_key.encode(),
        user.id,
        "account.retention.update",
        "user_account",
        user.id,
        "SUCCESS",
        request.state.correlation_id,
        {"scan_retention_days": body.days},
    )
    return payload


@router.delete("/account/scans")
def delete_account_scans(
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    _key: str = Depends(idempotency_key),
) -> JSONResponse:
    user = _fresh_account_user(db, principal)
    scans = list(db.scalars(select(Scan).where(Scan.owner_user_id == user.id).with_for_update()))
    now = datetime.now(UTC)
    run_ids: set[str] = set()
    scan_ids: list[str] = []
    for scan in scans:
        scan_ids.append(scan.id)
        run_ids.add(scan.run_id)
        scan.deleted_at = now
        scan.expires_at = now
        scan.original_ciphertext = "deleted"
        scan.enrichment_consent = False
    db.flush()
    if scan_ids:
        db.execute(
            update(SharedReport)
            .where(SharedReport.scan_id.in_(scan_ids), SharedReport.revoked_at.is_(None))
            .values(revoked_at=now)
        )
    service = _service(request, db)
    for run_id in run_ids:
        service.cancel_enrichment_if_unneeded(run_id)
    db.execute(delete(IdempotencyRecord).where(IdempotencyRecord.principal == principal.key))
    append_audit(
        db,
        request.app.state.settings.phishguard_hmac_key.encode(),
        user.id,
        "account.scans.delete",
        "user_account",
        user.id,
        "SUCCESS",
        request.state.correlation_id,
        {"scan_count": len(scans), "identity_platform_identity_deleted": False},
    )
    # The audit event is appended while its actor session is still attributable.
    # Revoke every application session after it; Identity Platform is untouched.
    db.execute(
        update(ApplicationSession)
        .where(ApplicationSession.user_id == user.id, ApplicationSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    response = JSONResponse(
        {
            "status": "deleted",
            "deleted_scan_count": len(scans),
            "application_sessions_revoked": True,
            "identity_platform_identity_deleted": False,
        }
    )
    _clear_session_cookies(response, request)
    return response


@router.post("/scans")
def create_scan(
    body: ScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal | None = Depends(get_principal),
    key: str = Depends(idempotency_key),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> JSONResponse:
    new_session: tuple[str, str] | None = None
    if not principal:
        principal, token, csrf = create_guest_session(db)
        new_session = (token, csrf)
    else:
        try:
            verify_csrf(db, principal, csrf_header)
        except PermissionError as exc:
            raise ApiError(403, "csrf_failed", "CSRF validation failed") from exc
    _consume_rate_limit(db, principal.key, request.app.state.settings.scan_rate_limit_per_minute)
    replay = _idempotent_replay(db, principal.key, "create_scan", key)
    if replay:
        response = JSONResponse(replay.response, status_code=replay.status_code)
        if new_session:
            _set_session_cookies(response, request, *new_session, 60 * 60)
        return response
    try:
        scan, decision, processing = _service(request, db).create(
            principal,
            body.url,
            body.analysis_mode,
            body.enrichment_consent,
        )
    except UrlPolicyError as exc:
        raise ApiError(422, exc.code, str(exc), {"url": str(exc)}) from exc
    except ValueError as exc:
        raise ApiError(422, "invalid_scan_request", str(exc)) from exc
    scan_payload = _scan_payload(scan, decision, "PROCESSING" if processing else "COMPLETE")
    status = 202 if processing else 201
    payload: dict[str, Any] = {"scan": scan_payload}
    if status == 202:
        payload["poll_after_ms"] = 1000
    _store_idempotency(db, principal.key, "create_scan", key, status, payload)
    response = JSONResponse(payload, status_code=status)
    if new_session:
        _set_session_cookies(response, request, *new_session, 60 * 60)
    return response


@router.get("/scans")
def list_scans(
    request: Request,
    limit: int = 50,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    service = _service(request, db)
    scans = service.list_authorized(principal, limit)
    items = []
    for scan in scans:
        run = db.get(AnalysisRun, scan.run_id)
        status = _scan_status(db, scan)
        items.append(_scan_payload(scan, service.decision_for_scan(scan), status))
    return {"items": items, "count": len(items)}


@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal | None = Depends(get_principal),
) -> dict[str, Any]:
    service = _service(request, db)
    scan = service.get_authorized(scan_id, principal)
    review_case_id: str | None = None
    if (
        not scan
        and principal
        and principal.role
        and principal.role.value in {"ANALYST", "ADMINISTRATOR"}
    ):
        candidate = db.get(Scan, scan_id)
        if candidate and not candidate.deleted_at and not _past(candidate.expires_at):
            review_case_id = db.scalar(
                select(ReviewCase.id).where(ReviewCase.scan_id == candidate.id).limit(1)
            )
            if review_case_id:
                scan = candidate
    if not scan:
        raise ApiError(404, "not_found", "Scan was not found")
    run = db.get(AnalysisRun, scan.run_id)
    assert run is not None
    decision = service.decision_for_scan(scan)
    evidence = [] if scan.requested_mode == "LOCAL_ONLY" or not decision.evidence_ids else [
        _evidence_payload(item)
        for item in db.scalars(
            select(EvidenceObservation)
            .where(EvidenceObservation.id.in_(decision.evidence_ids))
            .order_by(EvidenceObservation.family)
        )
    ]
    status = _scan_status(db, scan)
    payload = _scan_payload(scan, decision, status, evidence)
    response = {"scan": payload}
    if status in {"QUEUED", "LEASED"}:
        response["poll_after_ms"] = 1000
    if review_case_id:
        append_audit(
            db,
            request.app.state.settings.phishguard_hmac_key.encode(),
            principal.user_id,
            "scan.review.read",
            "scan",
            scan.id,
            "SUCCESS",
            request.state.correlation_id,
            {"review_case_id": review_case_id},
        )
    return response


@router.delete("/scans/{scan_id}", status_code=204, response_class=Response, response_model=None)
def delete_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
) -> None:
    scan = _service(request, db).get_authorized(scan_id, principal)
    if not scan:
        raise ApiError(404, "not_found", "Scan was not found")
    now = datetime.now(UTC)
    scan.deleted_at = now
    scan.expires_at = now
    scan.original_ciphertext = "deleted"
    # Session autoflush is deliberately disabled. Make consent withdrawal
    # visible before deciding whether shared enrichment work can continue.
    db.flush()
    _service(request, db).cancel_enrichment_if_unneeded(scan.run_id)
    # Never replay a response that points at a scan the user has deleted.
    db.execute(
        delete(IdempotencyRecord).where(
            IdempotencyRecord.principal == principal.key,
            or_(
                IdempotencyRecord.operation == "create_scan",
                IdempotencyRecord.operation.like(f"%:{scan.id}"),
            ),
        )
    )


@router.get("/scans/{scan_id}/original-url")
def reveal_original_url(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal | None = Depends(get_principal),
) -> dict[str, str]:
    service = _service(request, db)
    scan = db.get(Scan, scan_id)
    if not scan_is_active(scan) or not principal:
        raise ApiError(404, "not_found", "Scan was not found")
    if principal.user_id:
        if scan.owner_user_id != principal.user_id:
            raise ApiError(404, "not_found", "Scan was not found")
        try:
            require_fresh_auth(db, principal)
        except PermissionError as exc:
            raise ApiError(403, "fresh_auth_required", "Authentication within the last five minutes is required") from exc
    elif scan.guest_session_id != principal.session_id:
        raise ApiError(404, "not_found", "Scan was not found")
    append_audit(
        db,
        request.app.state.settings.phishguard_hmac_key.encode(),
        principal.user_id,
        "scan.original_url.reveal",
        "scan",
        scan.id,
        "SUCCESS",
        request.state.correlation_id,
    )
    return {"url": service.reveal(scan)}


@router.post("/scans/{scan_id}/shares", status_code=201)
def share_scan(
    scan_id: str,
    body: ShareRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    replay = _idempotent_replay(db, principal.key, f"share:{scan_id}", key)
    if replay:
        return replay.response
    scan = _service(request, db).get_authorized(scan_id, principal)
    if not scan:
        raise ApiError(404, "not_found", "Scan was not found")
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(hours=body.expires_in_hours)
    db.add(SharedReport(scan_id=scan.id, token_hash=token_digest(token), expires_at=expires_at))
    payload = {"report_id": token, "expires_at": expires_at.isoformat()}
    _store_idempotency(db, principal.key, f"share:{scan_id}", key, 201, payload)
    return payload


@router.get("/reports/{report_id}")
def shared_report(report_id: str, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    report = db.scalar(select(SharedReport).where(SharedReport.token_hash == token_digest(report_id)))
    if not report or report.revoked_at or _past(report.expires_at):
        raise ApiError(404, "not_found", "Report was not found")
    scan = db.get(Scan, report.scan_id)
    if not scan or scan.deleted_at or _past(scan.expires_at):
        raise ApiError(404, "not_found", "Report was not found")
    decision = _service(request, db).decision_for_scan(scan)
    evidence = [
        _public_evidence_payload(item)
        for item in db.scalars(
            select(EvidenceObservation)
            .where(EvidenceObservation.id.in_(decision.evidence_ids))
            .order_by(EvidenceObservation.family)
        )
    ] if decision.evidence_ids else []
    return {
        "scan": _scan_payload(scan, decision, _scan_status(db, scan), evidence),
        "expires_at": report.expires_at.isoformat(),
    }


@router.post("/scans/{scan_id}/feedback", status_code=201)
def create_feedback(
    scan_id: str,
    body: FeedbackRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(csrf_guard),
    key: str = Depends(idempotency_key),
) -> dict[str, Any]:
    replay = _idempotent_replay(db, principal.key, f"feedback:{scan_id}", key)
    if replay:
        return replay.response
    scan = _service(request, db).get_authorized(scan_id, principal)
    if not scan:
        raise ApiError(404, "not_found", "Scan was not found")
    feedback = Feedback(scan_id=scan.id, author_user_id=principal.user_id, category=body.category, comment=body.comment)
    db.add(feedback)
    db.flush()
    case = ReviewCase(scan_id=scan.id, feedback_id=feedback.id)
    db.add(case)
    db.flush()
    payload = {"id": feedback.id, "status": feedback.status, "review_case_id": case.id}
    _store_idempotency(db, principal.key, f"feedback:{scan_id}", key, 201, payload)
    return payload


@router.get("/feedback/{feedback_id}")
def get_feedback(
    feedback_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    row = db.get(Feedback, feedback_id)
    privileged = principal.role and principal.role.value in {"ANALYST", "ADMINISTRATOR"}
    scan = db.get(Scan, row.scan_id) if row else None
    if (
        not row
        or not scan_is_active(scan)
        or not (privileged or principal.user_id and row.author_user_id == principal.user_id)
    ):
        raise ApiError(404, "not_found", "Feedback was not found")
    return {"id": row.id, "scan_id": row.scan_id, "category": row.category, "comment": row.comment, "status": row.status}


def _scan_summary(scan: Scan) -> dict[str, Any]:
    return {
        "id": scan.id,
        "display_url": scan.display_url,
        "requested_mode": scan.requested_mode.lower(),
        "created_at": scan.created_at.isoformat(),
        "expires_at": scan.expires_at.isoformat(),
    }


def _scan_payload(
    scan: Scan, decision: Decision, status: str, evidence: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    normalized_status = "PROCESSING" if status in {"QUEUED", "LEASED"} else "COMPLETE" if status == "LOCAL_COMPLETE" else status
    return {
        **_scan_summary(scan),
        "status": normalized_status,
        "updated_at": decision.created_at.isoformat(),
        "decision": _decision_payload(decision, evidence or []),
    }


def _scan_status(db: Session, scan: Scan) -> str:
    if scan.requested_mode == "LOCAL_ONLY":
        return "LOCAL_COMPLETE"
    run = db.get(AnalysisRun, scan.run_id)
    return run.status if run else "INCONCLUSIVE"


def _decision_payload(row: Decision, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "risk_band": row.risk_band,
        "analysis_scope": row.analysis_scope,
        "completion": row.completion,
        "engine_mode": row.engine_mode,
        "reasons": row.reasons,
        "counter_evidence": row.counter_evidence,
        "missing_evidence": row.missing_evidence,
        "limitations": row.limitations,
        "safe_actions": row.safe_actions,
        "evidence": evidence,
        "versions": {
            "policy": row.policy_version,
            "ruleset": row.ruleset_version,
            "model": row.model_version or "rule-only",
            "fusion": row.fusion_version,
        },
    }


def _evidence_payload(row: EvidenceObservation) -> dict[str, Any]:
    return {
        "id": row.id,
        "family": row.family.upper(),
        "label": row.family.replace("_", " ").title(),
        "state": row.state,
        "source": row.source,
        "value": json.dumps(row.value, sort_keys=True, separators=(",", ":"))[:2000],
        "observed_at": row.observed_at.isoformat() if row.observed_at else None,
        "retrieved_at": row.retrieved_at.isoformat(),
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "version": row.version,
        "cached": row.cached,
        "reason_code": row.reason_code,
    }


def _public_evidence_payload(row: EvidenceObservation) -> dict[str, Any]:
    """Project a pinned observation without exposing INTERNAL evidence values."""
    return {
        "id": row.id,
        "family": row.family.upper(),
        "label": row.family.replace("_", " ").title(),
        "state": row.state,
        "source": row.source,
        "value": "Detailed evidence is hidden in this shared report.",
        "observed_at": row.observed_at.isoformat() if row.observed_at else None,
        "version": row.version,
        "reason_code": row.reason_code,
    }


def _idempotent_replay(db: Session, principal: str, operation: str, key: str) -> IdempotencyRecord | None:
    row = db.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.principal == principal,
            IdempotencyRecord.operation == operation,
            IdempotencyRecord.key == key,
        )
    )
    if row and _past(row.expires_at):
        # Remove the expired unique key before a replacement is inserted.
        db.delete(row)
        db.flush()
        return None
    return row


def _store_idempotency(
    db: Session, principal: str, operation: str, key: str, status_code: int, payload: dict[str, Any]
) -> None:
    db.add(
        IdempotencyRecord(
            principal=principal,
            operation=operation,
            key=key,
            status_code=status_code,
            response=payload,
            expires_at=datetime.now(UTC) + timedelta(hours=24),
        )
    )


def _past(value: datetime) -> bool:
    return (value if value.tzinfo else value.replace(tzinfo=UTC)) <= datetime.now(UTC)


def _consume_rate_limit(db: Session, principal: str, limit: int) -> None:
    current = datetime.now(UTC).replace(second=0, microsecond=0)
    row = db.scalar(
        select(RateLimitBucket)
        .where(
            RateLimitBucket.principal == principal,
            RateLimitBucket.category == "scan",
            RateLimitBucket.window_start == current,
        )
        .with_for_update()
    )
    if not row:
        row = RateLimitBucket(principal=principal, category="scan", window_start=current, count=0)
        db.add(row)
        db.flush()
    if row.count >= limit:
        raise ApiError(429, "rate_limit_exceeded", "Scan rate limit exceeded; retry after the next minute")
    row.count += 1
