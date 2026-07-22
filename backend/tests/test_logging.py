from __future__ import annotations

import json
import logging

from phishguard.logging_config import UrlFreeJsonFormatter


def test_json_formatter_emits_only_allowlisted_context() -> None:
    record = logging.LogRecord("phishguard.test", logging.INFO, __file__, 1, "scan complete", (), None)
    record.correlation_id = "corr-1"
    record.job_id = "job-1"
    record.raw_url = "https://example.test/reset?token=secret"

    payload = json.loads(UrlFreeJsonFormatter().format(record))

    assert payload["correlation_id"] == "corr-1"
    assert payload["job_id"] == "job-1"
    assert "raw_url" not in payload
    assert "secret" not in json.dumps(payload)
