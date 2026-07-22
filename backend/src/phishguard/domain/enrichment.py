from __future__ import annotations

from datetime import UTC, datetime
from typing import Callable

from phishguard.domain.types import Evidence, EvidenceState, RuleHit

ENRICHMENT_RULESET_VERSION = "enrichment-rules-1"
MAX_ENRICHMENT_LOG_ODDS = 2.0
EXPECTED_ENRICHMENT_FAMILIES = frozenset({"reputation", "dns", "rdap", "tls", "redirect", "static_html"})


def evaluate_enrichment_rules(evidence: tuple[Evidence, ...]) -> tuple[RuleHit, ...]:
    """Convert bounded observations into trusted, versioned contributions."""
    evaluators: dict[str, Callable[[Evidence], tuple[RuleHit, ...]]] = {
        "dns": _dns_rules,
        "rdap": _rdap_rules,
        "tls": _tls_rules,
        "redirect": _redirect_rules,
        "static_html": _html_rules,
    }
    hits: dict[str, RuleHit] = {}
    for item in evidence:
        if item.state != EvidenceState.OBSERVED or item.family not in evaluators:
            continue
        for hit in evaluators[item.family](item):
            hits.setdefault(hit.code, hit)
    return tuple(hits.values())


def _hit(item: Evidence, code: str, weight: float, message: str) -> RuleHit:
    return RuleHit(code, weight, message, item.family, item.source, item.version)


def _dns_rules(item: Evidence) -> tuple[RuleHit, ...]:
    # A successful public DNS answer is provenance, not evidence that a site is safe.
    return ()


def _rdap_rules(item: Evidence) -> tuple[RuleHit, ...]:
    events = item.value.get("events")
    registered = _date(events.get("registration")) if isinstance(events, dict) else None
    reference = _utc(item.observed_at or item.retrieved_at)
    if registered and registered <= reference and (reference - registered).days < 30:
        return (_hit(item, "new_domain", 0.65, "The domain was registered within the last 30 days."),)
    return ()


def _tls_rules(item: Evidence) -> tuple[RuleHit, ...]:
    hits: list[RuleHit] = []
    if item.value.get("hostname_verified") is False:
        hits.append(_hit(item, "tls_hostname_unverified", 0.7, "The TLS certificate was not verified for this hostname."))
    expires = _date(item.value.get("not_after"))
    if expires and expires < _utc(item.observed_at or item.retrieved_at):
        hits.append(_hit(item, "tls_expired", 0.55, "The TLS certificate was expired when observed."))
    if item.value.get("version") in {"TLSv1", "TLSv1.1"}:
        hits.append(_hit(item, "legacy_tls", 0.3, "The server used an obsolete TLS protocol version."))
    return tuple(hits)


def _redirect_rules(item: Evidence) -> tuple[RuleHit, ...]:
    chain = item.value.get("chain")
    if isinstance(chain, list) and any(
        isinstance(hop, dict)
        and isinstance(hop.get("from_host"), str)
        and isinstance(hop.get("to_host"), str)
        and hop["from_host"].rstrip(".").lower() != hop["to_host"].rstrip(".").lower()
        for hop in chain[:3]
    ):
        return (_hit(item, "cross_host_redirect", 0.45, "The redirect chain crossed to a different hostname."),)
    count = item.value.get("count")
    if isinstance(count, int) and not isinstance(count, bool) and 2 <= count <= 3:
        return (_hit(item, "multiple_redirects", 0.2, "The destination used multiple redirects."),)
    return ()


def _html_rules(item: Evidence) -> tuple[RuleHit, ...]:
    hits: list[RuleHit] = []
    password_inputs = item.value.get("password_inputs")
    if isinstance(password_inputs, int) and not isinstance(password_inputs, bool) and password_inputs > 0:
        hits.append(_hit(item, "password_form", 0.55, "The page contains a password input."))
    external_actions = item.value.get("external_form_actions")
    if isinstance(external_actions, int) and not isinstance(external_actions, bool) and external_actions > 0:
        hits.append(
            _hit(item, "external_form_action", 0.75, "A form submits information to a different hostname.")
        )
    return tuple(hits)


def _date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = (
            datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
            if value.endswith(" GMT")
            else datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
    except ValueError:
        return None
    return _utc(parsed)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
