from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from phishguard.api.app import create_app
from phishguard.config import Settings
from phishguard.infrastructure.database import make_engine


@pytest.fixture
def app():
    key = base64.urlsafe_b64encode(bytes(range(32))).decode()
    settings = Settings(
        environment="test",
        database_url="sqlite://",
        cookie_secure=True,
        dev_auth_enabled=True,
        phishguard_hmac_key="test-hmac-key-with-enough-entropy",
        phishguard_encryption_key=key,
    )
    return create_app(settings, make_engine("sqlite://"))


@pytest.fixture
def client(app):
    with TestClient(app, base_url="https://testserver") as value:
        yield value

