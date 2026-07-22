from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

import idna

MAX_URL_CHARS = 4096
_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ENCODED_CONTROL = re.compile(r"%(?:0[0-9A-Fa-f]|1[0-9A-Fa-f]|7[fF])")
_AMBIGUOUS_INTEGER = re.compile(r"^(?:0[xX][0-9A-Fa-f]+|0[0-7]+|[0-9]+)$")
_NUMERIC_COMPONENT = re.compile(r"^(?:0[xX][0-9A-Fa-f]+|[0-9]+)$")


class UrlPolicyError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class NormalizedUrl:
    original: str
    normalized: str
    scheme: str
    ascii_host: str
    unicode_host: str
    port: int
    path: str
    query: str
    fragment: str
    display: str
    is_ip_literal: bool


def _validate_ipv4_shape(host: str) -> bool:
    if not all(char.isdigit() or char == "." for char in host):
        return False
    parts = host.split(".")
    if len(parts) != 4:
        raise UrlPolicyError("ambiguous_ip", "Ambiguous numeric host syntax is not allowed")
    if any(not part or len(part) > 1 and part.startswith("0") for part in parts):
        raise UrlPolicyError("ambiguous_ip", "Non-canonical IPv4 syntax is not allowed")
    if any(int(part) > 255 for part in parts):
        raise UrlPolicyError("invalid_host", "IPv4 address is out of range")
    return True


def _host(parsed: SplitResult) -> tuple[str, str, bool]:
    try:
        host = parsed.hostname
    except ValueError as exc:
        raise UrlPolicyError("invalid_authority", "Malformed URL authority") from exc
    if not host:
        raise UrlPolicyError("missing_host", "URL must include a host")
    if "%" in host:
        raise UrlPolicyError("ipv6_zone", "IPv6 zone identifiers are not allowed")
    if any(char.isspace() or unicodedata.category(char).startswith("C") for char in host):
        raise UrlPolicyError("invalid_host", "Host contains forbidden characters")

    raw_host = host.rstrip(".")
    if not raw_host:
        raise UrlPolicyError("missing_host", "URL must include a host")
    if _AMBIGUOUS_INTEGER.fullmatch(raw_host) and not _validate_ipv4_shape(raw_host):
        raise UrlPolicyError("ambiguous_ip", "Ambiguous numeric host syntax is not allowed")
    numeric_parts = raw_host.split(".")
    if all(_NUMERIC_COMPONENT.fullmatch(part) for part in numeric_parts) and any(
        part.lower().startswith("0x") or len(part) > 1 and part.startswith("0") for part in numeric_parts
    ):
        raise UrlPolicyError("ambiguous_ip", "Legacy hexadecimal or octal IPv4 syntax is not allowed")

    try:
        canonical_v4 = _validate_ipv4_shape(raw_host)
        address = ipaddress.ip_address(raw_host) if canonical_v4 or ":" in raw_host else None
    except UrlPolicyError:
        raise
    except ValueError as exc:
        raise UrlPolicyError("invalid_host", "Invalid IP literal") from exc
    if address is not None:
        return address.compressed, address.compressed, True

    try:
        ascii_host = idna.encode(raw_host, uts46=True, std3_rules=True).decode("ascii").lower()
        unicode_host = idna.decode(ascii_host)
    except idna.IDNAError as exc:
        raise UrlPolicyError("invalid_idna", "Host is not valid IDNA") from exc
    if len(ascii_host) > 253:
        raise UrlPolicyError("host_too_long", "Host exceeds DNS limits")
    return ascii_host, unicode_host, False


def validate_url(value: str) -> NormalizedUrl:
    if not isinstance(value, str) or not value:
        raise UrlPolicyError("empty_url", "A URL is required")
    if len(value) > MAX_URL_CHARS:
        raise UrlPolicyError("url_too_long", f"URL exceeds {MAX_URL_CHARS} characters")
    if value != value.strip():
        raise UrlPolicyError("surrounding_whitespace", "URL must not contain surrounding whitespace")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise UrlPolicyError("control_character", "URL contains a control character")
    if _PERCENT.search(value) or _ENCODED_CONTROL.search(value):
        raise UrlPolicyError("invalid_encoding", "URL contains invalid or unsafe percent encoding")

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise UrlPolicyError("malformed_url", "URL could not be parsed") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UrlPolicyError("unsupported_scheme", "Only HTTP and HTTPS URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise UrlPolicyError("userinfo", "Credentials in URLs are not allowed")
    ascii_host, unicode_host, is_ip = _host(parsed)
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UrlPolicyError("invalid_port", "Port is invalid") from exc
    if port not in {80, 443}:
        raise UrlPolicyError("disallowed_port", "Only ports 80 and 443 are allowed")

    bracketed = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    default_port = 443 if scheme == "https" else 80
    authority = bracketed if port == default_port else f"{bracketed}:{port}"
    path = parsed.path or "/"
    normalized = urlunsplit((scheme, authority, path, parsed.query, parsed.fragment))
    display_host = unicode_host
    if unicode_host != ascii_host:
        display_host = f"{unicode_host} [{ascii_host}]"
    display_path = "/" if path == "/" else "/[path hidden]"
    query_notice = "?[query hidden]" if parsed.query else ""
    display = f"{scheme}://{display_host}{display_path}{query_notice}"
    return NormalizedUrl(
        original=value,
        normalized=normalized,
        scheme=scheme,
        ascii_host=ascii_host,
        unicode_host=unicode_host,
        port=port,
        path=path,
        query=parsed.query,
        fragment=parsed.fragment,
        display=display,
        is_ip_literal=is_ip,
    )


def url_fingerprint(normalized_url: str, key: bytes, policy_context: str) -> str:
    return hmac.new(key, f"{policy_context}\0{normalized_url}".encode(), hashlib.sha256).hexdigest()
