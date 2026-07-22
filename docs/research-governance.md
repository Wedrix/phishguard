# Research and model governance

## Dataset snapshots

Every snapshot is immutable and records: source and licence; acquisition interval; raw and processed SHA-256 hashes; row and domain counts; label definition; deduplication and conflict rules; preprocessing version; exclusions; class balance; and creator/approval. OpenPhish and Tranco data must not be redistributed beyond their terms. The evaluator rejects Google Web Risk in `source`, `label_source`, or `label_provenance`; runtime verdicts must never become training labels.

Split chronologically first, then prevent registrable-domain overlap across train, validation, and locked test sets. The evaluator reuses the checksum-verified, pinned Public Suffix List snapshot shipped with the fetcher and applies its complete ICANN section, including wildcard and exception rules; it never downloads suffix data at runtime. Private-section suffixes are grouped conservatively under their ICANN registrable domain, which can exclude extra rows but does not split sibling hostnames across partitions. Store the snapshot hash and split manifest before training. Feedback remains quarantined until independent adjudication and creation of a new approved snapshot.

## Experiments and model cards

Each run records source commit, environment lock, random seeds, snapshot/split hashes, feature schema, hyperparameters, runtime, and output hashes. Compare regularised logistic regression with histogram gradient boosting using recall, false-positive rate, PR-AUC, calibration, confidence intervals, robustness slices, and ablation. A candidate must pass governed recall, false-positive-rate, ECE, and Brier thresholds. The SRS does not currently state numeric ECE or Brier limits, so the evaluator records metrics but refuses to select or serialize a candidate until those two limits are explicitly supplied. Prefer logistic regression when the paired stratified-bootstrap 95% interval for the validation PR-AUC difference includes zero.

The model card records intended use, excluded use, training data, metrics and slices, calibration, threshold rationale, fairness/privacy/security limits, explainability method, owners, and rollback target. Activation requires an approved model checksum, artifact schema, exact model version, feature/preprocessing schema, calibration method, binary class order, locked scikit-learn version, and decision-policy version. Runtime checksum or metadata/schema failure produces visible rule-only mode. Because joblib artifacts are executable pickle data, only governance-approved checksums may be mounted; metadata validation is not a substitute for provenance approval.

The initial demo deliberately runs `RULE_ONLY`; no unapproved model is fabricated. To activate an approved model, upload `url_model.joblib` to `gs://PROJECT_ID-phishguard-models/active/`, create the namespaced `active-model` Secret with all three values `MODEL_PATH=/models/active/url_model.joblib`, `MODEL_SHA256=<approved hash>`, and `MODEL_VERSION=<approved version>`, then deploy with `KUSTOMIZE_OVERLAY=demo-model`. The overlay mounts the versioned model bucket read-only. Partial configuration fails startup. An unreadable, checksum-mismatched, or schema-mismatched fully configured artefact is rejected and the service remains available in visibly labelled `RULE_ONLY` fallback mode; it is never silently treated as the approved model.

## Controlled change

Provider, data, feature, model, threshold, retention, identity, or fusion changes require an SRS/RTM impact entry, ADR when architectural, threat-model review, test evidence, and rollback instructions. Preserve old immutable decisions; rescoring creates a new decision linked through `supersedes_id`.
