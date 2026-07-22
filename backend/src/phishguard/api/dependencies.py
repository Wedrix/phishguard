from __future__ import annotations

from collections.abc import Iterator

from fastapi import Cookie, Depends, Header, Request
from sqlalchemy.orm import Session

from phishguard.application.auth import Principal, resolve_principal, verify_csrf
from phishguard.api.errors import ApiError

HOST_SESSION_COOKIE = "__Host-phishguard_session"
DEV_SESSION_COOKIE = "phishguard_session"
CSRF_COOKIE = "phishguard_csrf"


def get_db(request: Request) -> Iterator[Session]:
    db = request.app.state.session_factory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_principal(
    request: Request,
    db: Session = Depends(get_db),
    host_session_token: str | None = Cookie(default=None, alias=HOST_SESSION_COOKIE),
    dev_session_token: str | None = Cookie(default=None, alias=DEV_SESSION_COOKIE),
) -> Principal | None:
    session_token = host_session_token if request.app.state.settings.cookie_secure else dev_session_token
    return resolve_principal(db, session_token)


def session_cookie_name(request: Request) -> str:
    return HOST_SESSION_COOKIE if request.app.state.settings.cookie_secure else DEV_SESSION_COOKIE


def require_principal(principal: Principal | None = Depends(get_principal)) -> Principal:
    if not principal:
        raise ApiError(401, "authentication_required", "Authentication or a valid guest session is required")
    return principal


def csrf_guard(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> Principal:
    try:
        verify_csrf(db, principal, csrf_header)
    except PermissionError as exc:
        raise ApiError(403, "csrf_failed", "CSRF validation failed") from exc
    return principal


def idempotency_key(value: str | None = Header(default=None, alias="Idempotency-Key")) -> str:
    if not value or not 8 <= len(value) <= 128:
        raise ApiError(400, "idempotency_key_required", "Idempotency-Key must contain 8 to 128 characters")
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise ApiError(400, "invalid_idempotency_key", "Idempotency-Key contains invalid characters")
    return value
