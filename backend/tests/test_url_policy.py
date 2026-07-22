from __future__ import annotations

import pytest

from phishguard.domain.url_policy import UrlPolicyError, url_fingerprint, validate_url


def test_normalization_and_redaction_do_not_expose_query_or_fragment() -> None:
    parsed = validate_url("HTTPS://Bücher.example/account/login?token=secret#private")
    assert parsed.ascii_host == "xn--bcher-kva.example"
    assert parsed.normalized == "https://xn--bcher-kva.example/account/login?token=secret#private"
    assert "secret" not in parsed.display
    assert "private" not in parsed.display
    assert "xn--bcher-kva.example" in parsed.display


@pytest.mark.parametrize(
    "url,code",
    [
        ("ftp://example.com/", "unsupported_scheme"),
        ("https://user:secret@example.com/", "userinfo"),
        ("http://2130706433/", "ambiguous_ip"),
        ("http://0x7f.0x0.0x0.0x1/", "ambiguous_ip"),
        ("http://0177.0.0.1/", "ambiguous_ip"),
        ("http://127.1/", "ambiguous_ip"),
        ("https://[fe80::1%25en0]/", "ipv6_zone"),
        ("https://example.com:8443/", "disallowed_port"),
        ("https://example.com/%0aheader", "invalid_encoding"),
    ],
)
def test_rejects_ambiguous_or_unsafe_urls(url: str, code: str) -> None:
    with pytest.raises(UrlPolicyError) as error:
        validate_url(url)
    assert error.value.code == code


def test_fingerprint_is_keyed_and_policy_scoped() -> None:
    first = url_fingerprint("https://example.com/", b"a" * 32, "v1")
    assert first != url_fingerprint("https://example.com/", b"b" * 32, "v1")
    assert first != url_fingerprint("https://example.com/", b"a" * 32, "v2")

