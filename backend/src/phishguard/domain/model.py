from __future__ import annotations

import hashlib
import hmac
import math
from pathlib import Path
from typing import Any, Protocol

import sklearn

from phishguard.domain.rules import LOCAL_FEATURE_SCHEMA, RULESET_VERSION, local_features
from phishguard.domain.url_policy import NormalizedUrl

MODEL_ARTIFACT_SCHEMA = "phishguard-url-model-v1"
MODEL_CALIBRATION_METHOD = "sigmoid-two-fold-training-only"


class UrlModel(Protocol):
    version: str

    def score(self, url: NormalizedUrl) -> float: ...


class SklearnUrlModel:
    """Checksum-verified, in-process scikit-learn probability model."""

    def __init__(self, path: Path, sha256: str, version: str):
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(actual, sha256.lower()):
            raise ValueError("model checksum mismatch")
        import joblib

        artifact: Any = joblib.load(path)
        if not isinstance(artifact, dict) or artifact.get("artifact_schema") != MODEL_ARTIFACT_SCHEMA:
            raise ValueError("unsupported model artifact schema")
        metadata = artifact.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError("model metadata is missing")
        expected = {
            "model_version": version,
            "feature_version": RULESET_VERSION,
            "feature_schema": list(LOCAL_FEATURE_SCHEMA),
            "sklearn_version": sklearn.__version__,
            "classes": [0, 1],
            "calibration": MODEL_CALIBRATION_METHOD,
        }
        for key, expected_value in expected.items():
            if metadata.get(key) != expected_value:
                raise ValueError(f"model metadata mismatch: {key}")
        self._model = artifact.get("estimator")
        if not hasattr(self._model, "predict_proba"):
            raise ValueError("model does not provide predict_proba")
        classes = getattr(self._model, "classes_", None)
        if classes is None or list(classes) != [0, 1]:
            raise ValueError("model classes must be [0, 1]")
        self.version = version

    def score(self, url: NormalizedUrl) -> float:
        features = local_features(url)
        if tuple(features) != LOCAL_FEATURE_SCHEMA:
            raise ValueError("runtime feature schema mismatch")
        probabilities = self._model.predict_proba([features])
        if len(probabilities) != 1 or len(probabilities[0]) != 2:
            raise ValueError("model probability output must have shape (1, 2)")
        probability = float(probabilities[0][1])
        if not math.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError("model probability outside [0, 1]")
        return probability
