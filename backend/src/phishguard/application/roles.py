from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from phishguard.domain.types import Role
from phishguard.infrastructure.models import ApplicationSession, RoleRequest, UserAccount

REQUESTABLE_ROLES = {Role.ANALYST, Role.RESEARCHER}
ROLE_REQUEST_STATES = {"PENDING", "APPROVED", "REJECTED", "CANCELLED"}


class RoleRequestError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class RoleRequestRepository:
    def __init__(self, db: Session):
        self.db = db

    def pending_for_user(
        self,
        user_id: str,
        *,
        for_update: bool = False,
    ) -> RoleRequest | None:
        query = (
            select(RoleRequest)
            .where(RoleRequest.user_id == user_id, RoleRequest.state == "PENDING")
            .order_by(RoleRequest.requested_at.desc())
            .limit(1)
        )
        return self.db.scalar(query.with_for_update() if for_update else query)

    def latest_for_user(self, user_id: str) -> RoleRequest | None:
        return self.db.scalar(
            select(RoleRequest)
            .where(RoleRequest.user_id == user_id)
            .order_by(RoleRequest.requested_at.desc())
            .limit(1)
        )

    def get_for_update(self, request_id: str) -> RoleRequest | None:
        return self.db.scalar(
            select(RoleRequest).where(RoleRequest.id == request_id).with_for_update()
        )

    def list(self, state: str | None, limit: int = 100) -> list[RoleRequest]:
        query = select(RoleRequest).order_by(RoleRequest.requested_at.desc()).limit(limit)
        if state:
            query = query.where(RoleRequest.state == state)
        return list(self.db.scalars(query))


class RoleRequestService:
    def __init__(self, db: Session):
        self.db = db
        self.repository = RoleRequestRepository(db)

    def request(self, user: UserAccount, requested_role: str) -> tuple[RoleRequest, bool]:
        try:
            role = Role(requested_role)
        except ValueError as exc:
            raise RoleRequestError(
                "role_not_requestable",
                "Only Analyst or Researcher access may be requested",
            ) from exc
        if role not in REQUESTABLE_ROLES:
            raise RoleRequestError(
                "role_not_requestable",
                "Only Analyst or Researcher access may be requested",
            )
        locked_user = self.db.scalar(
            select(UserAccount).where(UserAccount.id == user.id).with_for_update()
        )
        if (
            not locked_user
            or locked_user.disabled_at
            or locked_user.role != Role.REGISTERED_USER.value
        ):
            raise RoleRequestError(
                "role_request_not_allowed",
                "Only an active Registered User may submit a role request",
            )
        # Locking the account serializes the pending-row check with creation.
        pending = self.repository.pending_for_user(locked_user.id)
        if pending:
            raise RoleRequestError(
                "role_request_conflict",
                "A pending role request already exists",
            )
        row = RoleRequest(user_id=locked_user.id, requested_role=role.value, state="PENDING")
        try:
            with self.db.begin_nested():
                self.db.add(row)
                self.db.flush()
        except IntegrityError as exc:
            raise RoleRequestError(
                "role_request_conflict",
                "A pending role request already exists",
            ) from exc
        return row, True

    def cancel(self, user: UserAccount, request_id: str) -> RoleRequest:
        row = self.repository.get_for_update(request_id)
        if not row or row.user_id != user.id or row.state != "PENDING":
            raise RoleRequestError("role_request_not_found", "Role request was not found")
        row.state = "CANCELLED"
        row.decided_at = datetime.now(UTC)
        row.decision_note = "Cancelled by requester"
        self.db.flush()
        return row

    def decide(
        self,
        actor: UserAccount,
        request_id: str,
        action: str,
        note: str | None,
    ) -> tuple[RoleRequest, UserAccount, bool]:
        row = self.db.get(RoleRequest, request_id)
        if not row or row.state != "PENDING":
            raise RoleRequestError("role_request_not_found", "Pending role request was not found")
        target = self.db.scalar(
            select(UserAccount).where(UserAccount.id == row.user_id).with_for_update()
        )
        if not target:
            raise RoleRequestError("role_request_not_found", "Pending role request was not found")
        row = self.repository.get_for_update(request_id)
        if not row or row.state != "PENDING" or row.user_id != target.id:
            raise RoleRequestError("role_request_not_found", "Pending role request was not found")
        if actor.id == target.id:
            raise RoleRequestError(
                "self_role_change_forbidden",
                "Administrators cannot decide their own role request",
            )
        normalized_action = action.upper()
        if normalized_action not in {"APPROVE", "REJECT"}:
            raise RoleRequestError("invalid_role_request_action", "Action must be APPROVE or REJECT")

        changed = False
        if normalized_action == "APPROVE":
            if target.disabled_at or target.role != Role.REGISTERED_USER.value:
                raise RoleRequestError(
                    "role_request_target_ineligible",
                    "The target account is not eligible for this role",
                )
            if not (target.email_verified and target.mfa_verified):
                raise RoleRequestError(
                    "privileged_assurance_required",
                    "Verified email and TOTP are required before assigning a privileged role",
                )
            changed = target.role != row.requested_role
            target.role = row.requested_role
            row.state = "APPROVED"
            if changed:
                self.revoke_sessions(target.id)
        else:
            row.state = "REJECTED"
        row.decided_at = datetime.now(UTC)
        row.decided_by_user_id = actor.id
        row.decision_note = note
        self.db.flush()
        return row, target, changed

    def approve_matching_pending(
        self,
        actor: UserAccount,
        target: UserAccount,
        assigned_role: str,
    ) -> RoleRequest | None:
        pending = self.repository.pending_for_user(target.id, for_update=True)
        if not pending or pending.requested_role != assigned_role:
            return None
        pending.state = "APPROVED"
        pending.decided_at = datetime.now(UTC)
        pending.decided_by_user_id = actor.id
        pending.decision_note = "Approved through user administration"
        return pending

    def revoke_sessions(self, user_id: str) -> None:
        self.db.execute(
            update(ApplicationSession)
            .where(
                ApplicationSession.user_id == user_id,
                ApplicationSession.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
        )


def role_request_payload(row: RoleRequest | None) -> dict[str, object] | None:
    if not row:
        return None
    return {
        "id": row.id,
        "user_id": row.user_id,
        "requested_role": row.requested_role,
        "state": row.state,
        "requested_at": row.requested_at.isoformat(),
        "decided_at": row.decided_at.isoformat() if row.decided_at else None,
        "decided_by_user_id": row.decided_by_user_id,
        "decision_note": row.decision_note,
    }
