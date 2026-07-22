from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

_ALLOWED_FIELDS = {
    "correlation_id",
    "job_id",
    "event_id",
    "event_hmac",
    "status",
    "code",
    "count",
    "duration_ms",
    "provider",
    "evidence_state",
    "risk_band",
    "model_version",
}


class UrlFreeJsonFormatter(logging.Formatter):
    """Emit allowlisted structured fields and never serialize request/URL data."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _ALLOWED_FIELDS:
            value = getattr(record, field, None)
            if isinstance(value, (str, int, float, bool)):
                payload[field] = value
        if record.exc_info and record.exc_info[0]:
            payload["error_type"] = record.exc_info[0].__name__
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(UrlFreeJsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
