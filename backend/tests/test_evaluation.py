from __future__ import annotations

import csv
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import pytest

from phishguard.domain.model import SklearnUrlModel
from phishguard.domain.url_policy import validate_url
from phishguard.evaluation import train as train_module
from phishguard.evaluation.train import (
    _partition_rows,
    _read_rows,
    _registrable_domain,
    _select,
    evaluate_dataset,
)


def _write_dataset(path: Path, *, timestamps: bool = True) -> None:
    fields = ["url", "label", "source", "dataset_version"]
    if timestamps:
        fields.append("observed_at")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for index in range(60):
            label = index % 2
            writer.writerow(
                {
                    "url": (
                        f"http://login-verify-{index}.evil{index}.test/account/password-reset?token={index}"
                        if label
                        else f"https://shop{index}.example{index}.org/products/item"
                    ),
                    "label": label,
                    "source": "feed-a" if index % 4 < 2 else "feed-b",
                    "dataset_version": "synthetic-fixture-v1",
                    **(
                        {
                            "observed_at": (
                                datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(hours=index)
                            ).isoformat()
                        }
                        if timestamps
                        else {}
                    ),
                }
            )


def test_evaluation_uses_validation_for_selection_and_reports_locked_test(tmp_path: Path) -> None:
    dataset = tmp_path / "fixture.csv"
    output = tmp_path / "output"
    _write_dataset(dataset)

    manifest = evaluate_dataset(
        dataset,
        output,
        max_expected_calibration_error=1.0,
        max_brier_score=1.0,
    )

    assert manifest["artifact_status"] == "RESEARCH_ONLY_NOT_APPROVED_FOR_PRODUCTION"
    assert manifest["split"]["temporal"] is True
    assert manifest["selection"]["selected"] == "logistic_regression"
    assert set(manifest["candidate_validation_metrics"]) == {
        "logistic_regression",
        "histogram_gradient_boosting",
    }
    assert manifest["locked_test"]["model"] == "logistic_regression"
    assert "histogram_gradient_boosting" not in manifest["locked_test"]
    assert manifest["locked_test"]["bootstrap_95_percent_ci"]["pr_auc"] == [1.0, 1.0]
    assert set(manifest["locked_test"]["by_source"]) == {"feed-a", "feed-b"}
    assert manifest["locked_test"]["robustness"]["rows"] == 12
    assert set(manifest["validation_ablation"]) == {
        "without_url_shape",
        "without_security_indicators",
    }
    assert manifest["reproducibility"]["model_seed"] == 20250722
    assert manifest["protocol"]["selection_gates"]["maximum_expected_calibration_error"] == 1.0
    assert manifest["protocol"]["statistical_equivalence"][
        "equivalent_when_interval_includes_zero"
    ] is True
    assert (output / "research_candidate.joblib").is_file()
    assert not (output / "url_model.joblib").exists()
    assert "NOT APPROVED FOR PRODUCTION" in (output / "MODEL_CARD.md").read_text()
    artifact = manifest["candidate_artifact"]
    model = SklearnUrlModel(output / artifact["file"], artifact["sha256"], artifact["model_version"])
    assert 0 <= model.score(validate_url("https://example.test/")) <= 1


def test_partitions_are_temporal_and_registrable_domain_disjoint(tmp_path: Path) -> None:
    dataset = tmp_path / "fixture.csv"
    _write_dataset(dataset)
    partitions, report = _partition_rows(_read_rows(dataset).rows)

    domains = [{row.domain for row in partition} for partition in partitions.values()]
    assert not (domains[0] & domains[1] or domains[0] & domains[2] or domains[1] & domains[2])
    assert max(row.observed_at for row in partitions["train"]) <= min(
        row.observed_at for row in partitions["validation"]
    )
    assert max(row.observed_at for row in partitions["validation"]) <= min(
        row.observed_at for row in partitions["locked_test"]
    )
    assert report["strategy"] == "chronological-60-20-20-then-domain-overlap-exclusion"
    assert report["domain_key"] == "registrable domain (pinned-icann-psl-2026-07-20)"


def test_missing_timestamps_are_reported_as_non_temporal(tmp_path: Path) -> None:
    dataset = tmp_path / "fixture.csv"
    _write_dataset(dataset, timestamps=False)
    partitions, report = _partition_rows(_read_rows(dataset).rows)

    assert report["temporal"] is False
    assert {row.domain for row in partitions["train"]}.isdisjoint(
        row.domain for row in partitions["locked_test"]
    )


def test_bad_metadata_and_failed_gates_do_not_select_a_model(tmp_path: Path) -> None:
    dataset = tmp_path / "mixed.csv"
    dataset.write_text(
        "url,label,observed_at\n"
        "https://one.example/,0,2025-01-01T00:00:00Z\n"
        "https://two.example/,1,\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="populated for every row"):
        _read_rows(dataset)

    selected, reason = _select(
        {
            "logistic_regression": {
                "pr_auc": 0.9,
                "recall": 0.7,
                "false_positive_rate": 0.0,
                "expected_calibration_error": 0.1,
                "brier": 0.1,
            },
            "histogram_gradient_boosting": {
                "pr_auc": 0.95,
                "recall": 1.0,
                "false_positive_rate": 0.3,
                "expected_calibration_error": 0.1,
                "brier": 0.1,
            },
        },
        max_expected_calibration_error=0.2,
        max_brier_score=0.2,
    )
    assert selected is None
    assert "No candidate met" in reason


def test_selection_requires_calibration_gates_and_prefers_equivalent_logistic() -> None:
    metrics = {
        "logistic_regression": {
            "pr_auc": 0.89,
            "recall": 0.9,
            "false_positive_rate": 0.1,
            "expected_calibration_error": 0.04,
            "brier": 0.08,
        },
        "histogram_gradient_boosting": {
            "pr_auc": 0.90,
            "recall": 0.9,
            "false_positive_rate": 0.1,
            "expected_calibration_error": 0.03,
            "brier": 0.07,
        },
    }

    selected, reason = _select(metrics)
    assert selected is None
    assert "not configured" in reason

    selected, reason = _select(
        metrics,
        max_expected_calibration_error=0.1,
        max_brier_score=0.1,
        pr_auc_difference_ci=(-0.02, 0.04),
    )
    assert selected == "logistic_regression"
    assert "statistically equivalent" in reason

    selected, _ = _select(
        metrics,
        max_expected_calibration_error=0.1,
        max_brier_score=0.1,
        pr_auc_difference_ci=(0.001, 0.04),
    )
    assert selected == "histogram_gradient_boosting"


def test_ungated_evaluation_reports_metrics_without_candidate(tmp_path: Path) -> None:
    dataset = tmp_path / "fixture.csv"
    output = tmp_path / "output"
    _write_dataset(dataset)

    manifest = evaluate_dataset(dataset, output)

    assert manifest["selection"]["selected"] is None
    assert "not configured" in manifest["selection"]["reason"]
    assert manifest["candidate_artifact"] is None
    assert not (output / "research_candidate.joblib").exists()

    with pytest.raises(ValueError, match="must be supplied together"):
        evaluate_dataset(dataset, tmp_path / "invalid", max_expected_calibration_error=0.2)


def test_google_web_risk_label_provenance_is_rejected(tmp_path: Path) -> None:
    for column in ("source", "label_source", "label_provenance"):
        dataset = tmp_path / f"{column}.csv"
        dataset.write_text(
            f"url,label,{column}\nhttps://example.test/,1,OpenPhish plus Google Web Risk API verdict\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="cannot use Google Web Risk"):
            _read_rows(dataset)


def test_registrable_domain_policy_uses_pinned_icann_psl_rules() -> None:
    assert _registrable_domain("login.accounts.example.com") == "example.com"
    assert _registrable_domain("login.example.co.uk") == "example.co.uk"
    assert _registrable_domain("research.example.edu.gh") == "example.edu.gh"
    assert _registrable_domain("foo.city.kawasaki.jp") == "city.kawasaki.jp"
    assert _registrable_domain("a.b.ck") == "a.b.ck"
    assert _registrable_domain("tenant.blogspot.com") == "blogspot.com"
    assert _registrable_domain("192.0.2.1") == "192.0.2.1"


def test_public_suffix_snapshot_checksum_is_enforced(tmp_path: Path, monkeypatch) -> None:
    snapshot = tmp_path / "public-suffix-list.dat"
    snapshot.write_text(
        "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n",
        encoding="utf-8",
    )
    train_module._public_suffix_rules.cache_clear()
    monkeypatch.setattr(train_module, "_public_suffix_path", lambda: snapshot)
    with pytest.raises(ValueError, match="checksum mismatch"):
        train_module._public_suffix_rules()
    train_module._public_suffix_rules.cache_clear()


def test_runtime_rejects_artifact_metadata_drift(tmp_path: Path) -> None:
    dataset = tmp_path / "fixture.csv"
    output = tmp_path / "output"
    _write_dataset(dataset)
    manifest = evaluate_dataset(
        dataset,
        output,
        max_expected_calibration_error=1.0,
        max_brier_score=1.0,
    )
    path = output / "research_candidate.joblib"
    artifact = joblib.load(path)
    artifact["metadata"]["feature_version"] = "unexpected-features"
    joblib.dump(artifact, path)
    checksum = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="feature_version"):
        SklearnUrlModel(path, checksum, manifest["candidate_artifact"]["model_version"])
