from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import platform
import random
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence
from urllib.parse import urlsplit, urlunsplit

import joblib
import idna
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix, recall_score
from sklearn.pipeline import make_pipeline

from phishguard.domain.model import MODEL_ARTIFACT_SCHEMA, MODEL_CALIBRATION_METHOD
from phishguard.domain.rules import LOCAL_FEATURE_SCHEMA, RULESET_VERSION, local_features
from phishguard.domain.url_policy import UrlPolicyError, validate_url

SEED = 20250722
BOOTSTRAP_SEED = 20250723
BOOTSTRAP_SAMPLES = 500
THRESHOLD = 0.5
MIN_RECALL = 0.80
MAX_FALSE_POSITIVE_RATE = 0.20
CSV_SCHEMA_VERSION = "phishguard-evaluation-csv-v1"
REGISTRABLE_DOMAIN_POLICY = "pinned-icann-psl-2026-07-20"
PUBLIC_SUFFIX_LIST_SHA256 = "bc29842a9ffd0b804db0094ba649d2365224f6b65cd415271dc90fa6005f2856"


@dataclass(frozen=True, slots=True)
class Row:
    url: str
    label: int
    domain: str
    observed_at: datetime | None
    source: str


@dataclass(frozen=True, slots=True)
class Dataset:
    rows: tuple[Row, ...]
    declared_version: str | None
    duplicate_rows_removed: int


def evaluate_dataset(
    dataset: Path,
    output_dir: Path,
    *,
    max_expected_calibration_error: float | None = None,
    max_brier_score: float | None = None,
) -> dict[str, Any]:
    """Run a leakage-resistant research evaluation and write unapproved candidate artifacts."""
    if (max_expected_calibration_error is None) != (max_brier_score is None):
        raise ValueError("ECE and Brier calibration gates must be supplied together")
    loaded = _read_rows(dataset)
    if len(loaded.rows) < 30 or {row.label for row in loaded.rows} != {0, 1}:
        raise ValueError("dataset must contain at least 30 unique valid rows and both labels")

    partitions, split_report = _partition_rows(loaded.rows)
    for name, rows in partitions.items():
        if len(rows) < 4 or {row.label for row in rows} != {0, 1}:
            raise ValueError(f"{name} partition must contain at least four rows and both labels")
    minimum_train_class = min(sum(row.label == label for row in partitions["train"]) for label in (0, 1))
    if minimum_train_class < 2:
        raise ValueError("training partition needs at least two rows of each label for calibration")

    features = {
        name: [local_features(validate_url(row.url)) for row in partitions[name]]
        for name in ("train", "validation")
    }
    labels = {name: [row.label for row in partitions[name]] for name in ("train", "validation")}
    models = {name: _model(name) for name in ("logistic_regression", "histogram_gradient_boosting")}
    validation: dict[str, dict[str, float | None]] = {}
    validation_probability: dict[str, Sequence[float]] = {}
    for name, model in models.items():
        model.fit(features["train"], labels["train"])
        probability = model.predict_proba(features["validation"])[:, 1]
        validation_probability[name] = probability
        validation[name] = _metrics(labels["validation"], probability)

    pr_auc_difference_ci = _paired_pr_auc_difference_interval(
        labels["validation"],
        validation_probability["histogram_gradient_boosting"],
        validation_probability["logistic_regression"],
    )
    selected, selection_reason = _select(
        validation,
        max_expected_calibration_error=max_expected_calibration_error,
        max_brier_score=max_brier_score,
        pr_auc_difference_ci=pr_auc_difference_ci,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    candidate_path = output_dir / "research_candidate.joblib"
    if candidate_path.exists():
        candidate_path.unlink()

    test_report: dict[str, Any] | None = None
    ablation: dict[str, Any] = {}
    model_hash: str | None = None
    model_version: str | None = None
    if selected:
        model = models[selected]
        test_rows = partitions["locked_test"]
        test_features = [local_features(validate_url(row.url)) for row in test_rows]
        test_labels = [row.label for row in test_rows]
        test_probability = model.predict_proba(test_features)[:, 1]
        test_report = {
            "model": selected,
            "metrics": _metrics(test_labels, test_probability),
            "bootstrap_95_percent_ci": _bootstrap_intervals(test_labels, test_probability),
            "by_source": _group_report(test_rows, test_probability, lambda row, _: row.source),
            "slices": _slice_report(test_rows, test_features, test_probability),
            "robustness": _fragment_robustness(model, test_rows, test_probability),
        }
        ablation = _ablation(selected, features, labels, validation[selected])
        model_version = f"research-candidate-{selected}-{RULESET_VERSION}"
        joblib.dump(
            {
                "artifact_schema": MODEL_ARTIFACT_SCHEMA,
                "metadata": {
                    "model_version": model_version,
                    "feature_version": RULESET_VERSION,
                    "feature_schema": list(LOCAL_FEATURE_SCHEMA),
                    "sklearn_version": sklearn.__version__,
                    "classes": [0, 1],
                    "calibration": MODEL_CALIBRATION_METHOD,
                },
                "estimator": model,
            },
            candidate_path,
        )
        model_hash = _sha256(candidate_path)

    normalized_hash = _json_hash([_row_record(row) for row in sorted(loaded.rows, key=_row_sort_key)])
    split_hashes = {
        name: _json_hash([_row_record(row) for row in rows]) for name, rows in partitions.items()
    }
    lock_path = _dependency_lock_path()
    manifest: dict[str, Any] = {
        "artifact_status": "RESEARCH_ONLY_NOT_APPROVED_FOR_PRODUCTION",
        "dataset": {
            "path_name": dataset.name,
            "raw_sha256": _sha256(dataset),
            "normalized_sha256": normalized_hash,
            "csv_schema_version": CSV_SCHEMA_VERSION,
            "declared_version": loaded.declared_version,
            "rows": len(loaded.rows),
            "domains": len({row.domain for row in loaded.rows}),
            "duplicate_rows_removed": loaded.duplicate_rows_removed,
            "class_counts": _class_counts(loaded.rows),
            "source_counts": _source_counts(loaded.rows),
            "label_provenance_policy": "Google Web Risk verdicts are rejected as training labels",
            "registrable_domain_policy": REGISTRABLE_DOMAIN_POLICY,
            "public_suffix_list_sha256": PUBLIC_SUFFIX_LIST_SHA256,
            "public_suffix_list_section": "ICANN",
            "full_icann_public_suffix_list_guarantee": True,
            "known_domain_isolation_limitation": (
                "Isolation follows the pinned PSL ICANN section. Private-section suffixes are grouped "
                "conservatively under their ICANN registrable domain, which can exclude extra rows but "
                "does not split sibling hostnames across partitions. Re-evaluate when the snapshot changes."
            ),
        },
        "split": split_report | {
            "partitions": {
                name: {
                    "rows": len(rows),
                    "domains": len({row.domain for row in rows}),
                    "class_counts": _class_counts(rows),
                    "sha256": split_hashes[name],
                }
                for name, rows in partitions.items()
            }
        },
        "protocol": {
            "feature_schema": list(LOCAL_FEATURE_SCHEMA),
            "feature_version": RULESET_VERSION,
            "calibration": "sigmoid, two-fold cross-validation on training partition only",
            "decision_threshold": THRESHOLD,
            "selection_data": "validation only",
            "locked_test_policy": "evaluated once, only after model-family selection",
            "selection_gates": {
                "minimum_recall": MIN_RECALL,
                "maximum_false_positive_rate": MAX_FALSE_POSITIVE_RATE,
                "maximum_expected_calibration_error": max_expected_calibration_error,
                "maximum_brier_score": max_brier_score,
                "calibration_thresholds_required_for_selection": True,
            },
            "statistical_equivalence": {
                "metric": "paired validation PR-AUC difference (histogram gradient boosting minus logistic regression)",
                "bootstrap_95_percent_ci": pr_auc_difference_ci,
                "equivalent_when_interval_includes_zero": True,
            },
            "bootstrap": {
                "method": "stratified percentile",
                "confidence": 0.95,
                "samples": BOOTSTRAP_SAMPLES,
            },
        },
        "candidate_validation_metrics": validation,
        "selection": {"selected": selected, "reason": selection_reason},
        "locked_test": test_report,
        "validation_ablation": ablation,
        "reproducibility": {
            "model_seed": SEED,
            "bootstrap_seed": BOOTSTRAP_SEED,
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "requirements_lock_sha256": _sha256(lock_path),
            "evaluation_code_sha256": _sha256(Path(__file__)),
        },
        "candidate_artifact": (
            {
                "file": candidate_path.name,
                "sha256": model_hash,
                "artifact_schema": MODEL_ARTIFACT_SCHEMA,
                "model_version": model_version,
            }
            if model_hash
            else None
        ),
    }
    data_card = _data_card(manifest)
    model_card = _model_card(manifest)
    (output_dir / "DATA_CARD.md").write_text(data_card, encoding="utf-8")
    (output_dir / "MODEL_CARD.md").write_text(model_card, encoding="utf-8")
    manifest["output_sha256"] = {
        "data_card": _sha256(output_dir / "DATA_CARD.md"),
        "model_card": _sha256(output_dir / "MODEL_CARD.md"),
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def _read_rows(path: Path) -> Dataset:
    rows: list[Row] = []
    seen_records: set[tuple[str, int, str | None, str]] = set()
    labels_by_url: dict[str, int] = {}
    versions: set[str] = set()
    duplicates = 0
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"url", "label"}.issubset(reader.fieldnames):
            raise ValueError("CSV requires url and label columns")
        for line, raw in enumerate(reader, 2):
            try:
                url = validate_url(raw["url"]).normalized
                label = int(raw["label"])
                if label not in {0, 1}:
                    raise ValueError("label must be 0 or 1")
                observed_at = _timestamp(raw.get("observed_at") or "")
                source = (raw.get("source") or "").strip() or "unknown"
                for field in ("source", "label_source", "label_provenance"):
                    if _is_web_risk_source(raw.get(field, "")):
                        raise ValueError(f"{field} cannot use Google Web Risk verdicts as labels")
                version = (raw.get("dataset_version") or "").strip()
            except (KeyError, TypeError, ValueError, UrlPolicyError) as exc:
                raise ValueError(f"invalid CSV row {line}: {exc}") from exc
            if version:
                versions.add(version)
            if url in labels_by_url and labels_by_url[url] != label:
                raise ValueError(f"conflicting labels for normalized URL at CSV row {line}")
            labels_by_url[url] = label
            record = (url, label, observed_at.isoformat() if observed_at else None, source)
            if record in seen_records:
                duplicates += 1
                continue
            seen_records.add(record)
            rows.append(
                Row(
                    url,
                    label,
                    _registrable_domain(urlsplit(url).hostname or ""),
                    observed_at,
                    source,
                )
            )
    if len(versions) > 1:
        raise ValueError("dataset_version must be consistent across the CSV")
    if any(row.observed_at is None for row in rows) and any(row.observed_at is not None for row in rows):
        raise ValueError("observed_at must be populated for every row or omitted for every row")
    return Dataset(tuple(rows), next(iter(versions), None), duplicates)


def _timestamp(value: str) -> datetime | None:
    if not value.strip():
        return None
    timestamp = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("observed_at must include a timezone")
    return timestamp


def _is_web_risk_source(value: str | None) -> bool:
    token = re.sub(r"[^a-z0-9]+", "", (value or "").casefold())
    return "webrisk" in token


def _registrable_domain(hostname: str) -> str:
    """Return eTLD+1 using the checksum-verified pinned ICANN Public Suffix List."""
    host = hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    rules, wildcards, exceptions = _public_suffix_rules()
    suffixes = [".".join(labels[index:]) for index in range(len(labels))]
    exception_lengths = [
        len(suffix.split(".")) for suffix in suffixes if suffix in exceptions
    ]
    if exception_lengths:
        suffix_labels = max(exception_lengths) - 1
    else:
        exact_lengths = [len(suffix.split(".")) for suffix in suffixes if suffix in rules]
        wildcard_lengths = [
            len(suffix.split(".")) + 1
            for suffix in suffixes[1:]
            if suffix in wildcards
        ]
        suffix_labels = max([1, *exact_lengths, *wildcard_lengths])
    return ".".join(labels[-(suffix_labels + 1) :])


@lru_cache(maxsize=1)
def _public_suffix_rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    path = _public_suffix_path()
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != PUBLIC_SUFFIX_LIST_SHA256:
        raise ValueError("public suffix snapshot checksum mismatch")
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    in_icann_section = False
    for raw_line in data.decode("utf-8").splitlines():
        line = raw_line.strip()
        if line == "// ===BEGIN ICANN DOMAINS===":
            in_icann_section = True
            continue
        if line == "// ===END ICANN DOMAINS===":
            break
        if not in_icann_section or not line or line.startswith("//"):
            continue
        target = exceptions if line.startswith("!") else wildcards if line.startswith("*.") else rules
        value = line[1:] if line.startswith("!") else line[2:] if line.startswith("*.") else line
        target.add(idna.encode(value, uts46=True).decode("ascii"))
    if not rules:
        raise ValueError("public suffix snapshot has no ICANN rules")
    return frozenset(rules), frozenset(wildcards), frozenset(exceptions)


def _public_suffix_path() -> Path:
    candidates = (
        Path("/app/backend/data/public-suffix-list.dat"),
        Path(__file__).resolve().parents[4]
        / "fetcher"
        / "src"
        / "phishguard_fetcher"
        / "data"
        / "public-suffix-list.dat",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("pinned public-suffix-list.dat is required for evaluation")


def _partition_rows(rows: Sequence[Row]) -> tuple[dict[str, list[Row]], dict[str, Any]]:
    names = ("train", "validation", "locked_test")
    if rows[0].observed_at is None:
        domains = sorted({row.domain for row in rows}, key=lambda value: hashlib.sha256(value.encode()).digest())
        first, second = max(1, len(domains) * 6 // 10), max(2, len(domains) * 8 // 10)
        domain_partition = {
            domain: names[0 if index < first else 1 if index < second else 2]
            for index, domain in enumerate(domains)
        }
        partitions = {name: [] for name in names}
        for row in sorted(rows, key=_row_sort_key):
            partitions[domain_partition[row.domain]].append(row)
        report = {
            "strategy": "deterministic-domain-disjoint-60-20-20",
            "temporal": False,
            "domain_key": f"registrable domain ({REGISTRABLE_DOMAIN_POLICY})",
            "excluded_cross_boundary_domains": 0,
            "excluded_cross_boundary_rows": 0,
        }
        return partitions, report

    ordered = sorted(rows, key=_row_sort_key)
    train_cutoff = ordered[max(0, len(ordered) * 6 // 10 - 1)].observed_at
    validation_cutoff = ordered[max(0, len(ordered) * 8 // 10 - 1)].observed_at
    assert train_cutoff is not None and validation_cutoff is not None
    provisional: dict[str, list[Row]] = {name: [] for name in names}
    for row in ordered:
        name = (
            "train"
            if row.observed_at <= train_cutoff
            else "validation"
            if row.observed_at <= validation_cutoff
            else "locked_test"
        )
        provisional[name].append(row)
    domain_membership: dict[str, set[str]] = defaultdict(set)
    for name, partition in provisional.items():
        for row in partition:
            domain_membership[row.domain].add(name)
    crossing = {domain for domain, membership in domain_membership.items() if len(membership) > 1}
    partitions = {
        name: [row for row in partition if row.domain not in crossing]
        for name, partition in provisional.items()
    }
    return partitions, {
        "strategy": "chronological-60-20-20-then-domain-overlap-exclusion",
        "temporal": True,
        "domain_key": f"registrable domain ({REGISTRABLE_DOMAIN_POLICY})",
        "train_cutoff": train_cutoff.isoformat(),
        "validation_cutoff": validation_cutoff.isoformat(),
        "excluded_cross_boundary_domains": len(crossing),
        "excluded_cross_boundary_rows": sum(row.domain in crossing for row in rows),
    }


def _model(name: str) -> CalibratedClassifierCV:
    estimator = (
        LogisticRegression(max_iter=1000, class_weight="balanced", C=1.0, random_state=SEED)
        if name == "logistic_regression"
        else HistGradientBoostingClassifier(max_iter=150, class_weight="balanced", random_state=SEED)
    )
    vectorizer = DictVectorizer(sparse=name == "logistic_regression")
    return CalibratedClassifierCV(make_pipeline(vectorizer, estimator), method="sigmoid", cv=2)


def _metrics(labels: Sequence[int], probability: Sequence[float]) -> dict[str, float | None]:
    prediction = [int(value >= THRESHOLD) for value in probability]
    classes = set(labels)
    tn, fp, _, _ = confusion_matrix(labels, prediction, labels=[0, 1]).ravel()
    return {
        "pr_auc": float(average_precision_score(labels, probability)) if classes == {0, 1} else None,
        "recall": float(recall_score(labels, prediction, zero_division=0)) if 1 in classes else None,
        "false_positive_rate": float(fp / (fp + tn)) if 0 in classes else None,
        "brier": float(brier_score_loss(labels, probability)),
        "expected_calibration_error": _calibration_error(labels, probability),
    }


def _calibration_error(labels: Sequence[int], probability: Sequence[float], bins: int = 10) -> float:
    total = len(labels)
    error = 0.0
    for index in range(bins):
        low, high = index / bins, (index + 1) / bins
        members = [i for i, value in enumerate(probability) if low <= value < high or index == bins - 1 and value == 1]
        if members:
            error += len(members) / total * abs(
                sum(labels[i] for i in members) / len(members)
                - sum(float(probability[i]) for i in members) / len(members)
            )
    return float(error)


def _select(
    metrics: dict[str, dict[str, float | None]],
    *,
    max_expected_calibration_error: float | None = None,
    max_brier_score: float | None = None,
    pr_auc_difference_ci: Sequence[float] | None = None,
) -> tuple[str | None, str]:
    if max_expected_calibration_error is None or max_brier_score is None:
        return (
            None,
            "No candidate selected because governed ECE and Brier calibration thresholds are not configured.",
        )
    if not 0 <= max_expected_calibration_error <= 1 or not 0 <= max_brier_score <= 1:
        raise ValueError("calibration gates must be within [0, 1]")
    eligible = {
        name: result
        for name, result in metrics.items()
        if result["recall"] is not None
        and result["false_positive_rate"] is not None
        and result.get("expected_calibration_error") is not None
        and result.get("brier") is not None
        and result["recall"] >= MIN_RECALL
        and result["false_positive_rate"] <= MAX_FALSE_POSITIVE_RATE
        and result["expected_calibration_error"] <= max_expected_calibration_error
        and result["brier"] <= max_brier_score
    }
    if not eligible:
        return None, "No candidate met the governed validation recall, false-positive-rate, ECE, and Brier gates."
    best = max(eligible, key=lambda name: float(eligible[name]["pr_auc"] or 0.0))
    logistic = eligible.get("logistic_regression")
    statistically_equivalent = (
        pr_auc_difference_ci is not None
        and len(pr_auc_difference_ci) == 2
        and pr_auc_difference_ci[0] <= 0 <= pr_auc_difference_ci[1]
    )
    if logistic and (best == "logistic_regression" or statistically_equivalent):
        reason = (
            "Logistic regression met all gates and had the highest validation PR-AUC."
            if best == "logistic_regression"
            else "Logistic regression met all gates and was statistically equivalent on paired validation PR-AUC."
        )
        return "logistic_regression", reason
    return best, "Highest validation PR-AUC among candidates meeting all four gates."


def _paired_pr_auc_difference_interval(
    labels: Sequence[int],
    candidate_probability: Sequence[float],
    logistic_probability: Sequence[float],
) -> list[float]:
    """Stratified paired bootstrap CI for candidate PR-AUC minus logistic PR-AUC."""
    if len(labels) != len(candidate_probability) or len(labels) != len(logistic_probability):
        raise ValueError("paired probability arrays must match labels")
    by_class = {
        label: [index for index, value in enumerate(labels) if value == label]
        for label in (0, 1)
    }
    if not all(by_class.values()):
        raise ValueError("paired PR-AUC interval requires both classes")
    rng = random.Random(BOOTSTRAP_SEED + 1)
    differences: list[float] = []
    for _ in range(BOOTSTRAP_SAMPLES):
        indices = [
            rng.choice(by_class[label])
            for label in (0, 1)
            for _ in by_class[label]
        ]
        sample_labels = [labels[index] for index in indices]
        candidate = average_precision_score(
            sample_labels, [candidate_probability[index] for index in indices]
        )
        logistic = average_precision_score(
            sample_labels, [logistic_probability[index] for index in indices]
        )
        differences.append(float(candidate - logistic))
    return [_percentile(differences, 0.025), _percentile(differences, 0.975)]


def _bootstrap_intervals(labels: Sequence[int], probability: Sequence[float]) -> dict[str, list[float]]:
    rng = random.Random(BOOTSTRAP_SEED)
    by_class = {label: [index for index, value in enumerate(labels) if value == label] for label in (0, 1)}
    samples: dict[str, list[float]] = defaultdict(list)
    for _ in range(BOOTSTRAP_SAMPLES):
        indices = [rng.choice(by_class[label]) for label in (0, 1) for _ in by_class[label]]
        result = _metrics([labels[i] for i in indices], [probability[i] for i in indices])
        for name, value in result.items():
            if value is not None:
                samples[name].append(value)
    return {name: [_percentile(values, 0.025), _percentile(values, 0.975)] for name, values in samples.items()}


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = quantile * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower))


def _group_report(
    rows: Sequence[Row], probability: Sequence[float], key: Callable[[Row, int], str]
) -> dict[str, Any]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        groups[key(row, index)].append(index)
    return {
        name: {
            "rows": len(indices),
            "class_counts": _class_counts([rows[index] for index in indices]),
            "metrics": _metrics(
                [rows[index].label for index in indices], [probability[index] for index in indices]
            ),
        }
        for name, indices in sorted(groups.items())
    }


def _slice_report(
    rows: Sequence[Row], features: Sequence[dict[str, float]], probability: Sequence[float]
) -> dict[str, Any]:
    predicates = {
        "http": lambda feature: feature["is_https"] == 0,
        "https": lambda feature: feature["is_https"] == 1,
        "ip_literal": lambda feature: feature["is_ip"] == 1,
        "punycode": lambda feature: feature["has_punycode"] == 1,
        "credential_lure": lambda feature: feature["has_lure_term"] == 1,
        "long_url_120_plus": lambda feature: feature["url_length"] >= 120,
    }
    report: dict[str, Any] = {}
    for name, predicate in predicates.items():
        indices = [index for index, feature in enumerate(features) if predicate(feature)]
        if indices:
            report[name] = {
                "rows": len(indices),
                "class_counts": _class_counts([rows[index] for index in indices]),
                "metrics": _metrics(
                    [rows[index].label for index in indices], [probability[index] for index in indices]
                ),
            }
    return report


def _fragment_robustness(
    model: Any, rows: Sequence[Row], baseline: Sequence[float]
) -> dict[str, float | int | str]:
    changed_urls = []
    for row in rows:
        parsed = urlsplit(row.url)
        changed_urls.append(urlunsplit(parsed._replace(fragment="phishguard-robustness-check")))
    changed_features = [local_features(validate_url(url)) for url in changed_urls]
    changed = model.predict_proba(changed_features)[:, 1]
    differences = [abs(float(after) - float(before)) for before, after in zip(baseline, changed, strict=True)]
    return {
        "perturbation": "append a label-preserving URL fragment",
        "rows": len(rows),
        "mean_absolute_probability_change": sum(differences) / len(differences),
        "maximum_absolute_probability_change": max(differences),
        "decision_flip_rate": sum(
            (before >= THRESHOLD) != (after >= THRESHOLD)
            for before, after in zip(baseline, changed, strict=True)
        )
        / len(rows),
    }


def _ablation(
    selected: str,
    features: dict[str, list[dict[str, float]]],
    labels: dict[str, list[int]],
    baseline: dict[str, float | None],
) -> dict[str, Any]:
    groups = {
        "without_url_shape": {"url_length", "host_length", "path_length", "label_count", "entropy"},
        "without_security_indicators": {"is_https", "is_ip", "has_punycode", "has_lure_term"},
    }
    report: dict[str, Any] = {}
    for name, removed in groups.items():
        model = _model(selected)
        train = [{key: value for key, value in row.items() if key not in removed} for row in features["train"]]
        validation = [
            {key: value for key, value in row.items() if key not in removed}
            for row in features["validation"]
        ]
        model.fit(train, labels["train"])
        result = _metrics(labels["validation"], model.predict_proba(validation)[:, 1])
        report[name] = {
            "removed_features": sorted(removed),
            "validation_metrics": result,
            "pr_auc_change_from_full": (
                float(result["pr_auc"] - baseline["pr_auc"])
                if result["pr_auc"] is not None and baseline["pr_auc"] is not None
                else None
            ),
        }
    return report


def _row_record(row: Row) -> dict[str, Any]:
    return {
        "url": row.url,
        "label": row.label,
        "observed_at": row.observed_at.isoformat() if row.observed_at else None,
        "source": row.source,
    }


def _row_sort_key(row: Row) -> tuple[str, str, int, str]:
    return (row.observed_at.isoformat() if row.observed_at else "", row.url, row.label, row.source)


def _class_counts(rows: Iterable[Row]) -> dict[str, int]:
    values = list(rows)
    return {"0": sum(row.label == 0 for row in values), "1": sum(row.label == 1 for row in values)}


def _source_counts(rows: Iterable[Row]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        counts[row.source] += 1
    return dict(sorted(counts.items()))


def _json_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dependency_lock_path() -> Path:
    """Find the exported lock in editable checkouts and installed containers."""
    candidates = [Path.cwd() / "requirements.lock"]
    candidates.extend(parent / "requirements.lock" for parent in Path(__file__).resolve().parents)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("requirements.lock is required to create a reproducible experiment manifest")


def _data_card(manifest: dict[str, Any]) -> str:
    dataset = manifest["dataset"]
    split = manifest["split"]
    return f"""# Data card (research snapshot)

Status: **research input; approval and licence review required**

- CSV schema: `{dataset['csv_schema_version']}` (`url`, `label`; optional `observed_at`, `source`, `label_source`, `label_provenance`, `dataset_version`)
- Declared dataset version: `{dataset['declared_version'] or 'not supplied'}`
- Raw SHA-256: `{dataset['raw_sha256']}`
- Rows/domains: {dataset['rows']} / {dataset['domains']}
- Labels: {dataset['class_counts']}
- Sources: {dataset['source_counts']}
- Label provenance control: {dataset['label_provenance_policy']}
- Split: {split['strategy']}; temporal={str(split['temporal']).lower()}; domain key={split['domain_key']}
- Cross-boundary exclusions: {split['excluded_cross_boundary_rows']} rows from {split['excluded_cross_boundary_domains']} domains
- Residual leakage risk: **{dataset['known_domain_isolation_limitation']}**

## Required human completion before approval

- Provenance, acquisition interval, source licences, and redistribution constraints: PENDING (DEBT-009)
- Label definitions and independent adjudication method: PENDING (DEBT-009)
- Population coverage, sampling bias, exclusions, and known gaps: PENDING (DEBT-009)
- Privacy review, retention, owner, and approval record: PENDING (DEBT-009)

Limitation: `{dataset['registrable_domain_policy']}` uses the checksum-verified PSL ICANN section.
Private-section suffixes are deliberately grouped under their ICANN registrable domain. This is
conservative for leakage prevention but can exclude more rows than a private-suffix-aware split.
Review and version the split again whenever the pinned snapshot changes.
"""


def _model_card(manifest: dict[str, Any]) -> str:
    selection = manifest["selection"]
    return f"""# Model card (research candidate)

Status: **RESEARCH ONLY — NOT APPROVED FOR PRODUCTION**

- Selected family: `{selection['selected'] or 'none'}`
- Selection basis: {selection['reason']}
- Threshold: {manifest['protocol']['decision_threshold']}
- Calibration: {manifest['protocol']['calibration']}
- Validation metrics: see `manifest.json` → `candidate_validation_metrics`
- Locked-test metrics, confidence intervals, source/slice results, and robustness check: see `manifest.json` → `locked_test`
- Validation ablation: see `manifest.json` → `validation_ablation`

## Intended use

Offline experimental baseline for URL-only phishing research. It may support comparison with local rules after governance approval.

## Excluded use

Production activation, autonomous blocking, ground-truth generation, or decisions about people. This artifact has no approval status.

## Required human completion before approval

- Dataset/licence approval, metric interpretation, threshold rationale, and acceptance sign-off: PENDING (DEBT-009)
- Fairness, privacy, security, drift, and adversarial-evasion review: PENDING (DEBT-009)
- Explainability review, accountable owners, monitoring, rollback target, and decision-policy version: PENDING (DEBT-009)
"""
