from __future__ import annotations

import hashlib
import hmac
import json

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from phishguard.infrastructure.models import AuditEvent


def append_audit(
    db: Session,
    key: bytes,
    actor_user_id: str | None,
    action: str,
    object_type: str,
    object_id: str | None,
    outcome: str,
    correlation_id: str,
    detail: dict[str, object] | None = None,
) -> AuditEvent:
    if db.get_bind().dialect.name == "postgresql":
        # Serialise the chain head without depending on a row that does not yet
        # exist. The transaction-scoped lock is released automatically.
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": 0x504849534847})
    head = select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(1)
    # The PostgreSQL advisory lock already serialises writers. FOR UPDATE would
    # require UPDATE privilege on this append-only table and break least-privilege
    # runtime roles, which intentionally have only SELECT and INSERT.
    if db.get_bind().dialect.name != "postgresql":
        head = head.with_for_update()
    previous = db.scalar(head)
    previous_hmac = previous.event_hmac if previous else None
    body = json.dumps(
        {
            "actor": actor_user_id,
            "action": action,
            "object_type": object_type,
            "object_id": object_id,
            "outcome": outcome,
            "correlation_id": correlation_id,
            "detail": detail or {},
            "previous": previous_hmac,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    event = AuditEvent(
        actor_user_id=actor_user_id,
        action=action[:128],
        object_type=object_type[:64],
        object_id=object_id,
        outcome=outcome[:24],
        correlation_id=correlation_id,
        detail=detail or {},
        previous_hmac=previous_hmac,
        event_hmac=hmac.new(key, body.encode(), hashlib.sha256).hexdigest(),
    )
    db.add(event)
    db.flush()
    return event


def verify_audit_chain(rows: list[AuditEvent], key: bytes) -> tuple[bool, str | None]:
    previous_hmac: str | None = None
    for row in rows:
        body = json.dumps(
            {
                "actor": row.actor_user_id,
                "action": row.action,
                "object_type": row.object_type,
                "object_id": row.object_id,
                "outcome": row.outcome,
                "correlation_id": row.correlation_id,
                "detail": row.detail,
                "previous": previous_hmac,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
        if row.previous_hmac != previous_hmac or not hmac.compare_digest(row.event_hmac, expected):
            return False, row.id
        previous_hmac = row.event_hmac
    return True, None
