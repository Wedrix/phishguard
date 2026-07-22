from __future__ import annotations

import base64
import hashlib
import os
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class UrlCipher(Protocol):
    def encrypt(self, plaintext: str, context: str) -> str: ...

    def decrypt(self, ciphertext: str, context: str) -> str: ...


class LocalCipher:
    """AES-GCM fallback for development and non-GCP deployments."""

    def __init__(self, key: str):
        try:
            raw = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        except ValueError as exc:
            raise ValueError("PHISHGUARD_ENCRYPTION_KEY must be URL-safe base64") from exc
        if len(raw) != 32:
            raise ValueError("PHISHGUARD_ENCRYPTION_KEY must decode to 32 bytes")
        self._aes = AESGCM(raw)

    def encrypt(self, plaintext: str, context: str) -> str:
        nonce = os.urandom(12)
        value = nonce + self._aes.encrypt(nonce, plaintext.encode(), context.encode())
        return "local:v1:" + base64.urlsafe_b64encode(value).decode().rstrip("=")

    def decrypt(self, ciphertext: str, context: str) -> str:
        prefix = "local:v1:"
        if not ciphertext.startswith(prefix):
            raise ValueError("unsupported ciphertext envelope")
        encoded = ciphertext[len(prefix) :]
        value = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        return self._aes.decrypt(value[:12], value[12:], context.encode()).decode()


class KmsCipher:
    """Google Cloud KMS adapter using context as authenticated data."""

    def __init__(self, key_name: str):
        from google.cloud import kms

        self._client = kms.KeyManagementServiceClient()
        self._key_name = key_name

    def encrypt(self, plaintext: str, context: str) -> str:
        response = self._client.encrypt(
            request={"name": self._key_name, "plaintext": plaintext.encode(), "additional_authenticated_data": context.encode()}
        )
        return "kms:v1:" + base64.urlsafe_b64encode(response.ciphertext).decode().rstrip("=")

    def decrypt(self, ciphertext: str, context: str) -> str:
        prefix = "kms:v1:"
        if not ciphertext.startswith(prefix):
            raise ValueError("unsupported ciphertext envelope")
        encoded = ciphertext[len(prefix) :]
        response = self._client.decrypt(
            request={
                "name": self._key_name,
                "ciphertext": base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)),
                "additional_authenticated_data": context.encode(),
            }
        )
        return response.plaintext.decode()


def configured_cipher(kms_key_name: str | None, local_key: str | None, environment: str) -> UrlCipher:
    if kms_key_name:
        return KmsCipher(kms_key_name)
    if local_key:
        return LocalCipher(local_key)
    if environment in {"development", "test"}:
        # ponytail: deterministic dev key only; require KMS or an explicit random key outside local development.
        fallback = base64.urlsafe_b64encode(hashlib.sha256(b"phishguard-local-development-only").digest()).decode()
        return LocalCipher(fallback)
    raise RuntimeError("KMS_KEY_NAME or PHISHGUARD_ENCRYPTION_KEY is required")

