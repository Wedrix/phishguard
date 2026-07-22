from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

import aiohttp
import idna


@dataclass(frozen=True, slots=True)
class RdapResult:
    source: str
    value: dict[str, object]


class RdapBootstrap:
    """Queries an authoritative RDAP service selected from a pinned IANA snapshot."""

    MAX_RESPONSE_BYTES = 262_144

    def __init__(self, snapshot_path: Path | None = None, suffix_path: Path | None = None) -> None:
        path = snapshot_path or Path(__file__).with_name("data") / "iana-rdap-dns.json"
        self._snapshot = json.loads(path.read_text(encoding="utf-8"))
        psl_path = suffix_path or Path(__file__).with_name("data") / "public-suffix-list.dat"
        self._suffix_rules, self._wildcard_rules, self._exception_rules = self._load_suffixes(psl_path)

    @staticmethod
    def _load_suffixes(path: Path) -> tuple[set[str], set[str], set[str]]:
        rules: set[str] = set()
        wildcards: set[str] = set()
        exceptions: set[str] = set()
        in_icann_section = False
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line == "// ===BEGIN ICANN DOMAINS===":
                in_icann_section = True
                continue
            if line == "// ===END ICANN DOMAINS===":
                break
            if not in_icann_section or not line or line.startswith("//"):
                continue
            if line.startswith("!"):
                exceptions.add(idna.encode(line[1:], uts46=True).decode("ascii"))
            elif line.startswith("*."):
                wildcards.add(idna.encode(line[2:], uts46=True).decode("ascii"))
            else:
                rules.add(idna.encode(line, uts46=True).decode("ascii"))
        if not rules:
            raise ValueError("public suffix snapshot has no ICANN rules")
        return rules, wildcards, exceptions

    def endpoint_for(self, hostname: str) -> str | None:
        hostname = hostname.rstrip(".").lower()
        for tlds, endpoints in self._snapshot.get("services", []):
            if any(hostname == suffix or hostname.endswith(f".{suffix}") for suffix in tlds):
                for endpoint in endpoints:
                    value = str(endpoint).rstrip("/") + "/"
                    parsed = urlsplit(value)
                    if parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password:
                        return value
        return None

    def registrable_domain_for(self, hostname: str) -> str:
        labels = hostname.rstrip(".").lower().split(".")
        suffixes = [".".join(labels[index:]) for index in range(len(labels))]
        exception_lengths = [len(suffix.split(".")) for suffix in suffixes if suffix in self._exception_rules]
        if exception_lengths:
            suffix_labels = max(exception_lengths) - 1
        else:
            exact_lengths = [len(suffix.split(".")) for suffix in suffixes if suffix in self._suffix_rules]
            wildcard_lengths = [
                len(suffix.split(".")) + 1 for suffix in suffixes[1:] if suffix in self._wildcard_rules
            ]
            suffix_labels = max([1, *exact_lengths, *wildcard_lengths])
        return ".".join(labels[-(suffix_labels + 1) :]) if len(labels) > suffix_labels else hostname

    async def query(self, hostname: str, session: aiohttp.ClientSession) -> RdapResult | None:
        endpoint = self.endpoint_for(hostname)
        if endpoint is None:
            return None
        url = f"{endpoint}domain/{quote(hostname, safe='')}"
        async with session.get(url, allow_redirects=False) as response:
            if response.status != 200:
                return None
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                return None
            if response.content_length is not None and response.content_length > self.MAX_RESPONSE_BYTES:
                return None
            body = bytearray()
            async for chunk in response.content.iter_chunked(16_384):
                body.extend(chunk)
                if len(body) > self.MAX_RESPONSE_BYTES:
                    return None
            try:
                payload = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None
        if not isinstance(payload, dict):
            return None
        status = payload.get("status", [])
        events_payload = payload.get("events", [])
        nameservers_payload = payload.get("nameservers", [])
        if not isinstance(status, list) or not isinstance(events_payload, list) or not isinstance(nameservers_payload, list):
            return None
        events = {
            item["eventAction"][:80]: item.get("eventDate", "")[:80]
            for item in events_payload[:12]
            if isinstance(item, dict)
            and isinstance(item.get("eventAction"), str)
            and isinstance(item.get("eventDate", ""), str)
        }
        nameservers = [
            item["ldhName"][:253]
            for item in nameservers_payload[:12]
            if isinstance(item, dict) and isinstance(item.get("ldhName"), str)
        ]
        return RdapResult(
            source=endpoint,
            value={
                "handle_present": isinstance(payload.get("handle"), str) and bool(payload["handle"]),
                "status": [item[:80] for item in status[:12] if isinstance(item, str)],
                "events": events,
                "nameservers": nameservers,
                "queried_at": datetime.now(UTC).isoformat(),
            },
        )
