from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from phishguard.api.app import create_app
from phishguard.api import app as app_module
from phishguard.api import routes as routes_module
from phishguard.application.auth import IdentityClaims
from phishguard.config import Settings
from phishguard.infrastructure.database import make_engine
from phishguard.infrastructure.models import ApplicationSession


def _settings(*, cookie_secure: bool, identity_project_id: str | None = None) -> Settings:
    return Settings(
        environment="test",
        database_url="sqlite://",
        cookie_secure=cookie_secure,
        identity_project_id=identity_project_id,
        dev_auth_enabled=True,
        phishguard_hmac_key="test-hmac-key-with-enough-entropy",
        phishguard_encryption_key=base64.urlsafe_b64encode(bytes(range(32))).decode(),
    )


def test_local_http_uses_a_non_host_prefixed_session_cookie() -> None:
    app = create_app(_settings(cookie_secure=False), make_engine("sqlite://"))
    with TestClient(app, base_url="http://testserver") as client:
        created = client.post(
            "/api/v1/scans",
            headers={"Idempotency-Key": "local-http-cookie"},
            json={"url": "https://example.test/", "analysis_mode": "local_only", "enrichment_consent": False},
        )
        assert created.status_code == 201
        assert "phishguard_session" in client.cookies
        assert "__Host-phishguard_session" not in client.cookies
        assert client.get("/api/v1/me").status_code == 200


def test_csp_allows_only_the_identity_platform_connections_needed_by_the_spa() -> None:
    app = create_app(
        _settings(cookie_secure=True, identity_project_id="phishguard-example"),
        make_engine("sqlite://"),
    )
    with TestClient(app, base_url="https://testserver") as client:
        headers = client.get("/healthz").headers
        csp = headers["content-security-policy"]
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "https://identitytoolkit.googleapis.com" in csp
    assert "https://securetoken.googleapis.com" in csp
    assert "frame-src 'self' https://phishguard-example.firebaseapp.com" in csp
    assert "style-src 'self';" in csp
    assert "unsafe-inline" not in csp


def test_invalid_approved_model_degrades_to_rule_only(monkeypatch, tmp_path: Path) -> None:
    model_path = tmp_path / "bad-model.joblib"
    model_path.write_bytes(b"not a model")

    class BrokenModel:
        def __init__(self, *_args, **_kwargs):
            raise ValueError("invalid model")

    monkeypatch.setattr(app_module, "SklearnUrlModel", BrokenModel)
    settings = _settings(cookie_secure=True).model_copy(
        update={
            "model_path": model_path,
            "model_sha256": "0" * 64,
            "model_version": "rejected-v1",
        }
    )
    app = create_app(settings, make_engine("sqlite://"))
    assert app.state.model is None


def test_reauthentication_preserves_identity_claim_time(monkeypatch) -> None:
    app = create_app(_settings(cookie_secure=True), make_engine("sqlite://"))
    with TestClient(app, base_url="https://testserver") as client:
        signed_in = client.post(
            "/api/v1/session",
            json={"id_token": "dev:user@example.test:reauth-subject"},
        )
        assert signed_in.status_code == 201
        claim_time = datetime.now(UTC) - timedelta(minutes=4, seconds=59)
        monkeypatch.setattr(
            routes_module,
            "verify_identity_token",
            lambda *_args, **_kwargs: IdentityClaims(
                "reauth-subject",
                "user@example.test",
                True,
                True,
                claim_time,
            ),
        )
        response = client.post(
            "/api/v1/session/reauth",
            headers={"X-CSRF-Token": client.cookies["phishguard_csrf"]},
            json={"id_token": "verified-token-value-123"},
        )
        assert response.status_code == 200
        with app.state.session_factory() as db:
            row = db.scalar(select(ApplicationSession).where(ApplicationSession.user_id.is_not(None)))
            assert row is not None
            stored = row.reauthenticated_at
            assert stored is not None
            if not stored.tzinfo:
                stored = stored.replace(tzinfo=UTC)
            assert abs((stored - claim_time).total_seconds()) < 0.01


def test_cors_origins_environment_accepts_a_bounded_comma_separated_value(monkeypatch) -> None:
    monkeypatch.setenv("CORS_ORIGINS", "https://one.example, https://two.example")
    settings = Settings(
        environment="test",
        database_url="sqlite://",
        phishguard_hmac_key="test-hmac-key-with-enough-entropy",
    )
    assert settings.cors_origins == ["https://one.example", "https://two.example"]
