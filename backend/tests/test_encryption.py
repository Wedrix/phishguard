from __future__ import annotations

import base64

import pytest

from phishguard.infrastructure.encryption import LocalCipher


def test_local_cipher_authenticates_context_and_ciphertext() -> None:
    cipher = LocalCipher(base64.urlsafe_b64encode(bytes(range(32))).decode())
    encrypted = cipher.encrypt("https://example.com/?secret=1", "scan-1")
    assert "example.com" not in encrypted
    assert cipher.decrypt(encrypted, "scan-1") == "https://example.com/?secret=1"
    with pytest.raises(Exception):
        cipher.decrypt(encrypted, "scan-2")

