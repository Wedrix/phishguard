from __future__ import annotations

import math
import re

from phishguard.domain.types import RuleHit
from phishguard.domain.url_policy import NormalizedUrl

RULESET_VERSION = "local-rules-1"
LOCAL_FEATURE_SCHEMA = (
    "url_length",
    "host_length",
    "path_length",
    "label_count",
    "digit_ratio",
    "hyphen_count",
    "special_count",
    "is_https",
    "is_ip",
    "has_punycode",
    "has_lure_term",
    "entropy",
)
_LURE_TERMS = re.compile(
    r"(?:^|[-_.~/])(login|signin|verify|secure|account|wallet|password|update|confirm|invoice)(?:[-_.~/]|$)",
    re.IGNORECASE,
)


def local_features(url: NormalizedUrl) -> dict[str, float]:
    labels = url.ascii_host.split(".")
    text = f"{url.ascii_host}{url.path}"
    return {
        "url_length": float(len(url.normalized)),
        "host_length": float(len(url.ascii_host)),
        "path_length": float(len(url.path)),
        "label_count": float(len(labels)),
        "digit_ratio": sum(char.isdigit() for char in text) / max(1, len(text)),
        "hyphen_count": float(url.ascii_host.count("-")),
        "special_count": float(sum(url.normalized.count(char) for char in "@?=&%")),
        "is_https": float(url.scheme == "https"),
        "is_ip": float(url.is_ip_literal),
        "has_punycode": float("xn--" in url.ascii_host),
        "has_lure_term": float(bool(_LURE_TERMS.search(text))),
        "entropy": _entropy(text),
    }


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((value.count(char) / len(value)) * math.log2(value.count(char) / len(value)) for char in set(value))


def evaluate_local_rules(url: NormalizedUrl) -> tuple[RuleHit, ...]:
    features = local_features(url)
    checks = (
        (url.scheme == "http", "unencrypted_transport", 0.35, "The URL uses unencrypted HTTP."),
        (url.is_ip_literal, "ip_literal", 0.8, "The destination uses an IP address instead of a domain name."),
        ("xn--" in url.ascii_host, "punycode_host", 0.55, "The hostname contains an internationalised Punycode label."),
        (features["label_count"] >= 5, "many_subdomains", 0.3, "The hostname has an unusually deep subdomain structure."),
        (features["url_length"] >= 120, "long_url", 0.25, "The URL is unusually long."),
        (features["has_lure_term"] == 1, "credential_lure", 0.65, "The URL contains wording commonly used in credential lures."),
        (features["digit_ratio"] >= 0.3, "many_digits", 0.2, "The URL contains an unusually high proportion of digits."),
    )
    return tuple(RuleHit(code, weight, message) for matched, code, weight, message in checks if matched)
