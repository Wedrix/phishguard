from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from phishguard.application.auth import Principal
from phishguard.config import Settings
from phishguard.domain.enrichment import ENRICHMENT_RULESET_VERSION, EXPECTED_ENRICHMENT_FAMILIES
from phishguard.domain.fusion import FUSION_VERSION, decide
from phishguard.domain.model import UrlModel
from phishguard.domain.rules import RULESET_VERSION, evaluate_local_rules
from phishguard.domain.types import AnalysisScope, DecisionResult
from phishguard.domain.url_policy import NormalizedUrl, url_fingerprint, validate_url
from phishguard.infrastructure.encryption import UrlCipher
from phishguard.infrastructure.models import AnalysisRun, Decision, EvidenceObservation, Scan, ScanJob, UserAccount, new_id

POLICY_VERSION = "decision-policy-2"


class ScanService:
    def __init__(self, db: Session, settings: Settings, cipher: UrlCipher, model: UrlModel | None):
        self.db = db
        self.settings = settings
        self.cipher = cipher
        self.model = model

    def create(
        self,
        principal: Principal,
        raw_url: str,
        analysis_mode: str,
        enrichment_consent: bool,
    ) -> tuple[Scan, Decision, bool]:
        parsed = validate_url(raw_url)
        enriched = analysis_mode.lower() == "enriched"
        if analysis_mode.lower() not in {"local_only", "enriched"}:
            raise ValueError("analysis_mode must be local_only or enriched")
        if enriched and not enrichment_consent:
            raise ValueError("enriched analysis requires affirmative consent")
        if enriched and not self.settings.enrichment_enabled:
            raise ValueError("enrichment is disabled by policy")

        model_version = self.model.version if self.model else "rule-only"
        policy_context = f"{POLICY_VERSION}:{RULESET_VERSION}:{ENRICHMENT_RULESET_VERSION}:{model_version}"
        fingerprint = url_fingerprint(parsed.normalized, self.settings.phishguard_hmac_key.encode(), policy_context)
        run = self.db.scalar(
            select(AnalysisRun).where(
                AnalysisRun.fingerprint == fingerprint,
                AnalysisRun.policy_context == policy_context,
            )
        )
        decision: Decision | None = None
        if not run:
            run_id = new_id()
            run = AnalysisRun(
                id=run_id,
                fingerprint=fingerprint,
                policy_context=policy_context,
                normalized_ciphertext=self.cipher.encrypt(parsed.normalized, run_id),
            )
            self.db.add(run)
            self.db.flush()
            decision = self._local_decision(run, parsed)
        else:
            decision = self.db.scalar(
                select(Decision).where(Decision.run_id == run.id, Decision.stage == "LOCAL").order_by(Decision.created_at.desc())
            )
            if not decision:
                decision = self._local_decision(run, parsed)

        retention_days = self.settings.scan_retention_days
        if principal.user_id:
            user = self.db.get(UserAccount, principal.user_id)
            if user and user.scan_retention_days:
                retention_days = min(user.scan_retention_days, retention_days)
        scan_id = new_id()
        scan = Scan(
            id=scan_id,
            run_id=run.id,
            owner_user_id=principal.user_id,
            guest_session_id=None if principal.user_id else principal.session_id,
            original_ciphertext=self.cipher.encrypt(parsed.original, scan_id),
            display_url=parsed.display,
            requested_mode="ENRICHED" if enriched else "LOCAL_ONLY",
            enrichment_consent=enrichment_consent,
            notice_version=self.settings.notice_version if enriched else None,
            expires_at=datetime.now(UTC)
            + (timedelta(days=retention_days) if principal.user_id else timedelta(hours=1)),
        )
        self.db.add(scan)
        processing = False
        if enriched:
            existing = self.db.scalar(select(ScanJob).where(ScanJob.run_id == run.id, ScanJob.kind == "ENRICH"))
            if not existing:
                self.db.add(
                    ScanJob(
                        run_id=run.id,
                        deadline_at=datetime.now(UTC) + timedelta(minutes=2),
                    )
                )
                processing = True
                run.status = "QUEUED"
            elif existing.state in {"QUEUED", "LEASED"}:
                processing = True
                run.status = "QUEUED"
            elif existing.state == "COMPLETE":
                final = self.db.scalar(
                    select(Decision).where(Decision.run_id == run.id, Decision.stage == "FINAL").order_by(Decision.created_at.desc())
                )
                if final and _decision_evidence_is_fresh(self.db, final):
                    decision = final
                else:
                    _requeue(existing, run)
                    processing = True
            else:
                _requeue(existing, run)
                processing = True
        self.db.flush()
        return scan, decision, processing

    def _local_decision(self, run: AnalysisRun, parsed: NormalizedUrl) -> Decision:
        rules = evaluate_local_rules(parsed)
        model_probability: float | None = None
        if self.model:
            try:
                model_probability = self.model.score(parsed)
            except Exception:
                model_probability = None
        result = decide(rules, model_probability)
        decision = decision_row(
            run.id,
            result,
            "LOCAL",
            model_probability,
            rules,
            self.model.version if self.model and model_probability is not None else None,
        )
        self.db.add(decision)
        run.status = "LOCAL_COMPLETE"
        self.db.flush()
        return decision

    def get_authorized(self, scan_id: str, principal: Principal | None) -> Scan | None:
        scan = self.db.get(Scan, scan_id)
        if not scan_is_active(scan) or not principal:
            return None
        if principal.user_id and scan.owner_user_id == principal.user_id:
            return scan
        if not principal.user_id and scan.guest_session_id == principal.session_id:
            return scan
        return None

    def latest_decision(self, run_id: str) -> Decision:
        decision = self.db.scalar(select(Decision).where(Decision.run_id == run_id).order_by(Decision.created_at.desc()))
        if not decision:
            raise LookupError("decision missing")
        return decision

    def decision_for_scan(self, scan: Scan) -> Decision:
        if scan.requested_mode == "LOCAL_ONLY":
            decision = self.db.scalar(
                select(Decision).where(Decision.run_id == scan.run_id, Decision.stage == "LOCAL").order_by(Decision.created_at.desc())
            )
            if decision:
                return decision
        return self.latest_decision(scan.run_id)

    def list_authorized(self, principal: Principal, limit: int = 50) -> list[Scan]:
        query = (
            select(Scan)
            .where(Scan.deleted_at.is_(None), Scan.expires_at > datetime.now(UTC))
            .order_by(Scan.created_at.desc())
            .limit(min(limit, 100))
        )
        if principal.user_id:
            query = query.where(Scan.owner_user_id == principal.user_id)
        else:
            query = query.where(Scan.guest_session_id == principal.session_id)
        return list(self.db.scalars(query))

    def reveal(self, scan: Scan) -> str:
        return self.cipher.decrypt(scan.original_ciphertext, scan.id)

    def cancel_enrichment_if_unneeded(self, run_id: str) -> None:
        lock_enrichment_consent(self.db, run_id)
        if active_enrichment_scan_exists(self.db, run_id):
            return
        job = self.db.scalar(
            select(ScanJob).where(ScanJob.run_id == run_id, ScanJob.kind == "ENRICH").with_for_update()
        )
        if not job or job.state not in {"QUEUED", "LEASED"}:
            return
        job.state = "CANCELLED"
        job.last_error_code = "consent_withdrawn"
        job.lease_owner = None
        job.lease_expires_at = None
        run = self.db.get(AnalysisRun, run_id)
        if run and run.status == "QUEUED":
            run.status = "LOCAL_COMPLETE"


def decision_row(
    run_id: str,
    result: DecisionResult,
    stage: str,
    model_probability: float | None,
    rules: tuple,
    model_version: str | None,
    supersedes_id: str | None = None,
    evidence_ids: list[str] | None = None,
    ruleset_version: str = RULESET_VERSION,
) -> Decision:
    return Decision(
        run_id=run_id,
        supersedes_id=supersedes_id,
        stage=stage,
        risk_band=result.risk_band.value,
        analysis_scope=result.analysis_scope.value,
        completion=result.completion.value,
        engine_mode=result.engine_mode.value,
        probability=result.probability,
        model_probability=model_probability,
        rule_hits=[asdict(item) for item in rules],
        evidence_ids=evidence_ids or [],
        policy_version=POLICY_VERSION,
        ruleset_version=ruleset_version,
        model_version=model_version,
        fusion_version=FUSION_VERSION,
        reasons=list(result.reasons),
        counter_evidence=list(result.counter_evidence),
        missing_evidence=list(result.missing_evidence),
        limitations=list(result.limitations),
        safe_actions=list(result.safe_actions),
    )


def _requeue(job: ScanJob, run: AnalysisRun) -> None:
    job.state = "QUEUED"
    job.attempts = 0
    job.available_at = datetime.now(UTC)
    job.deadline_at = datetime.now(UTC) + timedelta(minutes=2)
    job.lease_owner = None
    job.lease_expires_at = None
    job.last_error_code = None
    run.status = "QUEUED"


def _decision_evidence_is_fresh(db: Session, decision: Decision) -> bool:
    ids = set(decision.evidence_ids)
    if decision.completion != "COMPLETE" or not ids:
        return False
    rows = list(db.scalars(select(EvidenceObservation).where(EvidenceObservation.id.in_(ids))))
    now = datetime.now(UTC)
    cacheable_states = {"OBSERVED", "NO_MATCH", "NOT_APPLICABLE"}
    return (
        len(rows) == len(ids)
        and {row.family for row in rows} >= EXPECTED_ENRICHMENT_FAMILIES
        and all(
            row.run_id == decision.run_id
            and row.state in cacheable_states
            and bool(row.source.strip())
            and row.version.strip().lower() not in {"", "unknown"}
            and row.expires_at is not None
            and (row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)) > now
            for row in rows
        )
    )


def scan_is_active(scan: Scan | None, current: datetime | None = None) -> bool:
    if not scan or scan.deleted_at:
        return False
    expiry = scan.expires_at if scan.expires_at.tzinfo else scan.expires_at.replace(tzinfo=UTC)
    return expiry > (current or datetime.now(UTC))


def active_enrichment_scan_exists(db: Session, run_id: str, current: datetime | None = None) -> bool:
    return db.scalar(
        select(Scan.id)
        .where(
            Scan.run_id == run_id,
            Scan.requested_mode == "ENRICHED",
            Scan.enrichment_consent.is_(True),
            Scan.deleted_at.is_(None),
            Scan.expires_at > (current or datetime.now(UTC)),
        )
        .limit(1)
    ) is not None


def lock_enrichment_consent(db: Session, run_id: str) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:run_id, 0))"),
            {"run_id": run_id},
        )
