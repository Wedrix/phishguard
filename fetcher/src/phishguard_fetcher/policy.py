from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import SplitResult, urlsplit, urlunsplit

import dns.asyncresolver
import dns.exception
import idna

from .models import EvidenceState


class SafetyRejected(ValueError):
    """The target violates the outbound retrieval policy."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class DnsResolutionError(RuntimeError):
    """A closed DNS evidence outcome that prevented target retrieval."""

    def __init__(self, state: EvidenceState, reason_code: str) -> None:
        super().__init__(reason_code)
        self.state = state
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


class AddressResolver(Protocol):
    async def resolve(self, hostname: str) -> tuple[str, ...]: ...


class DnsAddressResolver:
    def __init__(self, lifetime_seconds: float = 1.5) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=True)
        self._resolver.lifetime = lifetime_seconds

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        queries = [self._lookup(hostname, "A"), self._lookup(hostname, "AAAA")]
        results = await asyncio.gather(*queries)
        addresses = tuple(dict.fromkeys(address for _, group in results for address in group))
        if not addresses:
            statuses = {status for status, _ in results}
            if "nxdomain" in statuses:
                raise DnsResolutionError(EvidenceState.NO_MATCH, "dns_nxdomain")
            if "timeout" in statuses:
                raise DnsResolutionError(EvidenceState.TIMED_OUT, "dns_timeout")
            if "unavailable" in statuses:
                raise DnsResolutionError(EvidenceState.UNAVAILABLE, "dns_unavailable")
            raise DnsResolutionError(EvidenceState.NO_MATCH, "dns_no_answer")
        return addresses

    async def _lookup(self, hostname: str, record_type: str) -> tuple[str, tuple[str, ...]]:
        try:
            answer = await self._resolver.resolve(hostname, record_type, search=False)
        except dns.resolver.NXDOMAIN:
            return "nxdomain", ()
        except dns.resolver.NoAnswer:
            return "no_answer", ()
        except (dns.exception.Timeout, TimeoutError):
            return "timeout", ()
        except (dns.resolver.NoNameservers, dns.exception.DNSException, OSError):
            return "unavailable", ()
        return "answered", tuple(str(item) for item in answer)


def is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
    )


def _normalise_hostname(hostname: str) -> str:
    if "%" in hostname:
        raise SafetyRejected("ipv6_zone_identifier", "IPv6 zone identifiers are not allowed")
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    try:
        return idna.encode(hostname.rstrip("."), uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise SafetyRejected("invalid_hostname", "The hostname is not valid IDNA") from exc


def _reject_ambiguous_ip_encoding(hostname: str) -> None:
    """Reject browser-compatible legacy numeric forms before DNS is attempted."""

    lowered = hostname.lower()
    labels = lowered.split(".")
    looks_numeric = lowered.isdecimal()
    looks_hex = lowered.startswith("0x") and all(char in "0123456789abcdefx" for char in lowered)
    dotted_numeric = all(
        label.isdecimal() or (label.startswith("0x") and all(char in "0123456789abcdefx" for char in label))
        for label in labels
    )
    if looks_numeric or looks_hex or dotted_numeric:
        try:
            canonical = str(ipaddress.IPv4Address(lowered))
        except ipaddress.AddressValueError:
            raise SafetyRejected("ambiguous_ip_encoding", "Legacy numeric IP encodings are not allowed") from None
        if lowered != canonical:
            raise SafetyRejected("ambiguous_ip_encoding", "Legacy numeric IP encodings are not allowed")


def parse_target(url: str, allowed_ports: tuple[int, ...]) -> SplitResult:
    if len(url) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise SafetyRejected("invalid_url", "The URL is too long or contains control characters")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise SafetyRejected("unsupported_scheme", "Only HTTP and HTTPS are allowed")
    if not parts.hostname or parts.username is not None or parts.password is not None:
        raise SafetyRejected("credentials_or_host_missing", "Credentials are forbidden and a host is required")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise SafetyRejected("invalid_port", "The target port is malformed") from exc
    if port not in allowed_ports:
        raise SafetyRejected("port_not_allowed", "The target port is not allowed")
    hostname = _normalise_hostname(parts.hostname)
    _reject_ambiguous_ip_encoding(hostname)
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if parts.scheme == "https" else 80
    netloc = display_host if port == default_port else f"{display_host}:{port}"
    return SplitResult(parts.scheme, netloc, parts.path or "/", parts.query, "")


async def resolve_and_validate(
    url: str,
    allowed_ports: tuple[int, ...],
    resolver: AddressResolver,
) -> ResolvedTarget:
    parts = parse_target(url, allowed_ports)
    assert parts.hostname is not None
    hostname = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        addresses = await resolver.resolve(hostname)
        if not addresses:
            raise DnsResolutionError(EvidenceState.NO_MATCH, "dns_no_answer")
    else:
        addresses = (str(literal),)

    if any(not is_public_address(address) for address in addresses):
        raise SafetyRejected("non_public_address", "The hostname resolved to a non-public address")
    return ResolvedTarget(urlunsplit(parts), hostname, port, addresses)


def socket_family(address: str) -> int:
    return socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
