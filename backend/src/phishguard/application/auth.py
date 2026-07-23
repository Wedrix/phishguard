from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishguard.domain.types import Role
from phishguard.infrastructure.models import ApplicationSession, Scan, UserAccount


class AuthenticationError(ValueError):
    pass


class AuthorizationError(PermissionError):
    pass


@dataclass(frozen=True, slots=True)
class IdentityClaims:
    subject: str
    email: str
    email_verified: bool
    mfa_verified: bool
    authenticated_at: datetime


@dataclass(frozen=True, slots=True)
class Principal:
    session_id: str
    user_id: str | None
    role: Role | None
    csrf_token: str | None = None

    @property
    def key(self) -> str:
        return f"user:{self.user_id}" if self.user_id else f"guest:{self.session_id}"


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def verify_identity_token(token: str, project_id: str | None, dev_auth_enabled: bool) -> IdentityClaims:
    if dev_auth_enabled and token.startswith("dev:"):
        parts = token.split(":", 2)
        if len(parts) != 3 or "@" not in parts[1]:
            raise AuthenticationError("invalid development identity token")
        return IdentityClaims(parts[2], parts[1].lower(), True, True, datetime.now(UTC))
    if not project_id:
        raise AuthenticationError("Identity Platform is not configured")
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.id_token import verify_firebase_token

        claims = verify_firebase_token(token, Request(), audience=project_id)
    except Exception as exc:
        raise AuthenticationError("ID token could not be verified") from exc
    if not claims or not claims.get("sub") or not claims.get("email"):
        raise AuthenticationError("ID token is missing required claims")
    firebase = claims.get("firebase", {})
    second_factor = firebase.get("sign_in_second_factor") or claims.get("sign_in_second_factor")
    mfa = isinstance(second_factor, str) and second_factor.lower() == "totp"
    try:
        authenticated_at = datetime.fromtimestamp(float(claims["auth_time"]), UTC)
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise AuthenticationError("ID token is missing a valid authentication time") from exc
    return IdentityClaims(
        str(claims["sub"]),
        str(claims["email"]).lower(),
        bool(claims.get("email_verified")),
        mfa,
        authenticated_at,
    )


def create_guest_session(db: Session) -> tuple[Principal, str, str]:
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    row = ApplicationSession(
        token_hash=token_digest(token),
        csrf_hash=token_digest(csrf),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db.add(row)
    db.flush()
    return Principal(row.id, None, None, csrf), token, csrf


def create_user_session(
    db: Session, claims: IdentityClaims, hmac_key: bytes
) -> tuple[Principal, str, str]:
    if not claims.email_verified:
        raise AuthenticationError("Email address must be verified")
    email_hash = hmac.new(hmac_key, claims.email.encode(), hashlib.sha256).hexdigest()
    user = db.scalar(select(UserAccount).where(UserAccount.identity_subject == claims.subject))
    if not user:
        user = UserAccount(
            identity_subject=claims.subject,
            email_hash=email_hash,
            role=Role.REGISTERED_USER.value,
            email_verified=True,
            mfa_verified=claims.mfa_verified,
        )
        db.add(user)
        db.flush()
    else:
        user.email_verified = True
        user.mfa_verified = claims.mfa_verified
    if user.disabled_at:
        raise AuthenticationError("Account is disabled")
    role = Role(user.role)
    if role in {Role.ANALYST, Role.ADMINISTRATOR, Role.RESEARCHER} and not claims.mfa_verified:
        raise AuthenticationError("Multi-factor authentication is required for this role")
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    row = ApplicationSession(
        user_id=user.id,
        token_hash=token_digest(token),
        csrf_hash=token_digest(csrf),
        expires_at=datetime.now(UTC) + timedelta(hours=8),
        reauthenticated_at=claims.authenticated_at,
    )
    db.add(row)
    db.flush()
    return Principal(row.id, user.id, role, csrf), token, csrf


def adopt_guest_scans(
    db: Session,
    guest_session_id: str,
    user_id: str,
    retention_days: int,
) -> int:
    guest_session = db.scalar(
        select(ApplicationSession)
        .where(
            ApplicationSession.id == guest_session_id,
            ApplicationSession.user_id.is_(None),
            ApplicationSession.revoked_at.is_(None),
        )
        .with_for_update()
    )
    if not guest_session:
        return 0
    current = datetime.now(UTC)
    scans = list(
        db.scalars(
            select(Scan)
            .where(
                Scan.guest_session_id == guest_session.id,
                Scan.owner_user_id.is_(None),
                Scan.deleted_at.is_(None),
                Scan.expires_at > current,
            )
            .with_for_update()
        )
    )
    registered_expiry = current + timedelta(days=retention_days)
    for scan in scans:
        scan.owner_user_id = user_id
        scan.guest_session_id = None
        expiry = scan.expires_at if scan.expires_at.tzinfo else scan.expires_at.replace(tzinfo=UTC)
        if expiry < registered_expiry:
            scan.expires_at = registered_expiry
    guest_session.revoked_at = current
    db.flush()
    return len(scans)


def resolve_principal(db: Session, token: str | None) -> Principal | None:
    if not token:
        return None
    row = db.scalar(select(ApplicationSession).where(ApplicationSession.token_hash == token_digest(token)))
    if not row or row.revoked_at:
        return None
    current = datetime.now(UTC)
    expiry = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
    if expiry <= current:
        return None
    if not row.user_id:
        row.last_seen_at = current
        return Principal(row.id, None, None)
    user = db.get(UserAccount, row.user_id)
    if not user or user.disabled_at:
        return None
    role = Role(user.role)
    if role in {Role.ANALYST, Role.ADMINISTRATOR, Role.RESEARCHER} and not (
        user.email_verified and user.mfa_verified
    ):
        return None
    last_seen = row.last_seen_at if row.last_seen_at.tzinfo else row.last_seen_at.replace(tzinfo=UTC)
    if role in {Role.ANALYST, Role.ADMINISTRATOR, Role.RESEARCHER} and last_seen < current - timedelta(minutes=30):
        return None
    row.last_seen_at = current
    return Principal(row.id, user.id, role)


def verify_csrf(db: Session, principal: Principal, supplied: str | None) -> None:
    row = db.get(ApplicationSession, principal.session_id)
    if not row or not supplied or not hmac.compare_digest(row.csrf_hash, token_digest(supplied)):
        raise AuthorizationError("CSRF validation failed")


def require_role(principal: Principal | None, *roles: Role) -> Principal:
    if not principal or principal.role not in roles:
        raise AuthorizationError("Insufficient permissions")
    return principal


def require_fresh_auth(db: Session, principal: Principal, minutes: int = 5) -> None:
    row = db.get(ApplicationSession, principal.session_id)
    if not row or not row.reauthenticated_at:
        raise AuthorizationError("Recent authentication is required")
    timestamp = row.reauthenticated_at
    if not timestamp.tzinfo:
        timestamp = timestamp.replace(tzinfo=UTC)
    if timestamp < datetime.now(UTC) - timedelta(minutes=minutes):
        raise AuthorizationError("Recent authentication is required")
