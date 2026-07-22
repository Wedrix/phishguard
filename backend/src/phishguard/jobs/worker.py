from __future__ import annotations

import asyncio
import logging
import socket
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import delete, or_, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from phishguard.config import Settings
from phishguard.domain.enrichment import ENRICHMENT_RULESET_VERSION, evaluate_enrichment_rules
from phishguard.domain.fusion import decide
from phishguard.domain.model import UrlModel
from phishguard.domain.rules import evaluate_local_rules
from phishguard.domain.types import AnalysisScope, Evidence, EvidenceState, RuleHit
from phishguard.domain.url_policy import validate_url
from phishguard.infrastructure.encryption import UrlCipher
from phishguard.infrastructure.models import (
    AnalysisRun,
    Decision,
    EvidenceObservation,
    ProviderConfig,
    RateLimitBucket,
    ScanJob,
)
from phishguard.infrastructure.providers import FetcherClient, WebRiskClient
from phishguard.application.scans import (
    active_enrichment_scan_exists,
    decision_row,
    lock_enrichment_consent,
)

logger = logging.getLogger(__name__)
MIN_JOB_LEASE_SECONDS = 30
DEFAULT_WEB_RISK_QUOTA_PER_MINUTE = 60
FETCHER_EVIDENCE_TTL = timedelta(minutes=15)


def lease_jobs(db: Session, owner: str, limit: int, lease_seconds: int) -> list[str]:
    current = datetime.now(UTC)
    lease_seconds = max(lease_seconds, MIN_JOB_LEASE_SECONDS)
    rows = list(
        db.scalars(
            select(ScanJob)
            .where(
                ScanJob.available_at <= current,
                or_(
                    ScanJob.state == "QUEUED",
                    (ScanJob.state == "LEASED") & (ScanJob.lease_expires_at < current),
                ),
            )
            .order_by(ScanJob.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    for row in rows:
        row.state = "LEASED"
        row.lease_owner = owner
        row.lease_expires_at = current + timedelta(seconds=lease_seconds)
        row.attempts += 1
    db.flush()
    return [row.id for row in rows]


async def process_job(
    factory: sessionmaker[Session],
    job_id: str,
    cipher: UrlCipher,
    model: UrlModel | None,
    web_risk: WebRiskClient,
    fetcher: FetcherClient,
    lease_owner: str | None = None,
    lease_seconds: int = MIN_JOB_LEASE_SECONDS,
) -> None:
    db = factory()
    try:
        job = db.get(ScanJob, job_id)
        if not job or job.state != "LEASED":
            return
        owner = lease_owner or job.lease_owner
        if not owner or job.lease_owner != owner:
            return
        deadline = job.deadline_at if job.deadline_at.tzinfo else job.deadline_at.replace(tzinfo=UTC)
        run = db.get(AnalysisRun, job.run_id)
        if not run:
            job = _owned_job(db, job_id, owner)
            if not job:
                db.rollback()
                return
            job.state = "FAILED"
            job.last_error_code = "run_missing"
            db.commit()
            return
        if not active_enrichment_scan_exists(db, run.id):
            job = _owned_job(db, job_id, owner)
            if job:
                _cancel_job(run, job)
                db.commit()
            else:
                db.rollback()
            return
        url = cipher.decrypt(run.normalized_ciphertext, run.id)
        parsed = urlsplit(url)
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        if deadline <= datetime.now(UTC):
            job = _owned_job(db, job_id, owner)
            if not job:
                db.rollback()
                return
            _finalize_missing(db, run, job, "job_deadline_exceeded", EvidenceState.TIMED_OUT)
            db.commit()
            return
        provider = db.scalar(select(ProviderConfig).where(ProviderConfig.provider == "google_web_risk"))
        reputation: Evidence | None = None
        if provider and not provider.enabled:
            reputation = Evidence(
                "reputation",
                EvidenceState.SKIPPED_POLICY,
                "google_web_risk",
                reason_code="provider_disabled",
            )
        else:
            quota = _web_risk_quota(provider)
            if quota is None:
                reputation = Evidence(
                    "reputation",
                    EvidenceState.UNAVAILABLE,
                    "google_web_risk",
                    reason_code="provider_quota_invalid",
                )
            else:
                try:
                    quota_available = _consume_web_risk_quota(db, quota)
                    db.commit()
                except SQLAlchemyError:
                    db.rollback()
                    quota_available = None
                if quota_available is False:
                    reputation = Evidence(
                        "reputation",
                        EvidenceState.SKIPPED_POLICY,
                        "google_web_risk",
                        reason_code="provider_quota_exhausted",
                    )
                elif quota_available is None:
                    reputation = Evidence(
                        "reputation",
                        EvidenceState.UNAVAILABLE,
                        "google_web_risk",
                        reason_code="provider_quota_unavailable",
                    )
        # Serialize the consent boundary through outbound work. Deletion takes
        # the same transaction-scoped advisory lock before it can return.
        lock_enrichment_consent(db, run.id)
        job = _current_owned_job(db, job_id, owner)
        if not job:
            db.rollback()
            return
        if not active_enrichment_scan_exists(db, run.id):
            _cancel_job(run, job)
            db.commit()
            return
        renewal_stop = asyncio.Event()
        renewal = asyncio.create_task(
            renew_job_lease(factory, job_id, owner, lease_seconds, renewal_stop)
        )
        try:
            if reputation is not None:
                fetched = await fetcher.enrich(url, run.id, job.id)
            else:
                reputation, fetched = await asyncio.gather(
                    web_risk.lookup(url),
                    fetcher.enrich(url, run.id, job.id),
                )
        finally:
            renewal_stop.set()
            await renewal
        evidence = (reputation, *fetched)
        job = _owned_job(db, job_id, owner)
        if not job:
            db.rollback()
            return
        evidence_rows = _store_evidence(db, run.id, evidence)

        local = db.scalar(
            select(Decision).where(Decision.run_id == run.id, Decision.stage == "LOCAL").order_by(Decision.created_at.desc())
        )
        if not local:
            raise RuntimeError("local decision missing")
        rules = tuple(RuleHit(**item) for item in local.rule_hits)
        enrichment_rules = evaluate_enrichment_rules(evidence)
        result = decide(rules, local.model_probability, evidence, AnalysisScope.ENRICHED, enrichment_rules)
        previous = db.scalar(select(Decision).where(Decision.run_id == run.id).order_by(Decision.created_at.desc()))
        db.add(
            decision_row(
                run.id,
                result,
                "FINAL",
                local.model_probability,
                (*rules, *enrichment_rules),
                local.model_version,
                supersedes_id=previous.id if previous else local.id,
                evidence_ids=[row.id for row in evidence_rows],
                ruleset_version=f"{local.ruleset_version}+{ENRICHMENT_RULESET_VERSION}",
            )
        )
        run.status = "PARTIAL" if result.completion.value == "PARTIAL" else "COMPLETE"
        job.state = "COMPLETE"
        job.lease_owner = None
        job.lease_expires_at = None
        db.commit()
    except Exception:
        db.rollback()
        retry = _owned_job(db, job_id, locals().get("owner"))
        if retry:
            if retry.attempts < 2:
                retry.state = "QUEUED"
                retry.available_at = datetime.now(UTC) + timedelta(seconds=2)
                retry.last_error_code = "worker_error"
                retry.lease_owner = None
                retry.lease_expires_at = None
            else:
                run = db.get(AnalysisRun, retry.run_id)
                if run:
                    _finalize_missing(db, run, retry, "worker_error", EvidenceState.UNAVAILABLE)
                else:
                    retry.state = "FAILED"
                    retry.last_error_code = "run_missing"
            db.commit()
        logger.exception("enrichment job failed", extra={"job_id": job_id})
    finally:
        db.close()


def _store_evidence(db: Session, run_id: str, evidence: tuple[Evidence, ...]) -> list[EvidenceObservation]:
    rows: list[EvidenceObservation] = []
    for item in evidence:
        expires_at = item.expires_at
        if (
            expires_at is None
            and item.state in {EvidenceState.OBSERVED, EvidenceState.NO_MATCH, EvidenceState.NOT_APPLICABLE}
            and item.source.startswith("isolated_fetcher:")
            and item.version.startswith("fetcher-")
        ):
            expires_at = item.retrieved_at + FETCHER_EVIDENCE_TTL
        row = EvidenceObservation(
                run_id=run_id,
                family=item.family,
                state=item.state.value,
                source=item.source,
                value=item.value,
                observed_at=item.observed_at,
                retrieved_at=item.retrieved_at,
                expires_at=expires_at,
                version=item.version,
                cached=item.cached,
                sensitivity=item.sensitivity,
                reason_code=item.reason_code,
            )
        db.add(row)
        rows.append(row)
    db.flush()
    return rows


def _finalize_missing(
    db: Session, run: AnalysisRun, job: ScanJob, reason: str, state: EvidenceState
) -> None:
    evidence = (
        Evidence("reputation", state, "google_web_risk", reason_code=reason),
        *(
            Evidence(family, state, "isolated_fetcher", reason_code=reason)
            for family in ("dns", "rdap", "tls", "redirect", "static_html")
        ),
    )
    evidence_rows = _store_evidence(db, run.id, evidence)
    local = db.scalar(
        select(Decision).where(Decision.run_id == run.id, Decision.stage == "LOCAL").order_by(Decision.created_at.desc())
    )
    if local:
        rules = tuple(RuleHit(**item) for item in local.rule_hits)
        result = decide(rules, local.model_probability, evidence, AnalysisScope.ENRICHED)
        previous = db.scalar(select(Decision).where(Decision.run_id == run.id).order_by(Decision.created_at.desc()))
        db.add(
            decision_row(
                run.id,
                result,
                "FINAL",
                local.model_probability,
                rules,
                local.model_version,
                supersedes_id=previous.id if previous else local.id,
                evidence_ids=[row.id for row in evidence_rows],
                ruleset_version=f"{local.ruleset_version}+{ENRICHMENT_RULESET_VERSION}",
            )
        )
        run.status = "PARTIAL"
    job.state = "COMPLETE"
    job.last_error_code = reason
    job.lease_owner = None
    job.lease_expires_at = None


def _cancel_job(run: AnalysisRun, job: ScanJob) -> None:
    job.state = "CANCELLED"
    job.last_error_code = "consent_withdrawn"
    job.lease_owner = None
    job.lease_expires_at = None
    if run.status == "QUEUED":
        run.status = "LOCAL_COMPLETE"


async def run_worker(
    settings: Settings,
    factory: sessionmaker[Session],
    cipher: UrlCipher,
    model: UrlModel | None,
    once: bool = False,
) -> None:
    owner = f"{socket.gethostname()}:{id(factory)}"
    web_risk = WebRiskClient(settings.web_risk_api_key, settings.web_risk_base_url)
    fetcher = FetcherClient(
        settings.fetcher_url,
        settings.fetcher_ca_file,
        settings.fetcher_cert_file,
        settings.fetcher_key_file,
    )
    while True:
        with factory.begin() as db:
            ids = lease_jobs(db, owner, settings.job_concurrency, settings.job_lease_seconds)
        if ids:
            await asyncio.gather(
                *(
                    process_job(
                        factory,
                        item,
                        cipher,
                        model,
                        web_risk,
                        fetcher,
                        owner,
                        settings.job_lease_seconds,
                    )
                    for item in ids
                )
            )
        if once:
            return
        await asyncio.sleep(settings.job_poll_seconds)


def cleanup_expired(db: Session) -> int:
    from sqlalchemy import func

    from phishguard.infrastructure.models import ApplicationSession, IdempotencyRecord, Scan

    current = datetime.now(UTC)
    scans = list(db.scalars(select(Scan).where(Scan.expires_at <= current)))
    run_ids = {scan.run_id for scan in scans}
    for scan in scans:
        db.delete(scan)
    db.flush()
    for run_id in run_ids:
        if not db.scalar(select(func.count()).select_from(Scan).where(Scan.run_id == run_id)):
            run = db.get(AnalysisRun, run_id)
            if run:
                db.delete(run)
    # These operational records are bounded state, not an archive. Expired
    # idempotency rows can contain result metadata and otherwise permanently
    # reserve their unique keys.
    db.execute(delete(IdempotencyRecord).where(IdempotencyRecord.expires_at <= current))
    db.execute(delete(ApplicationSession).where(ApplicationSession.expires_at <= current))
    db.execute(
        delete(RateLimitBucket).where(
            RateLimitBucket.window_start < current - timedelta(minutes=5)
        )
    )
    return len(scans)


def _owned_job(db: Session, job_id: str, owner: str | None) -> ScanJob | None:
    if not owner:
        return None
    job = db.scalar(
        select(ScanJob)
        .where(ScanJob.id == job_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if not job or job.state != "LEASED" or job.lease_owner != owner:
        return None
    expires = job.lease_expires_at
    if not expires or (expires if expires.tzinfo else expires.replace(tzinfo=UTC)) <= datetime.now(UTC):
        return None
    return job


def _current_owned_job(db: Session, job_id: str, owner: str | None) -> ScanJob | None:
    if not owner:
        return None
    job = db.scalar(
        select(ScanJob)
        .where(ScanJob.id == job_id)
        .execution_options(populate_existing=True)
    )
    if not job or job.state != "LEASED" or job.lease_owner != owner:
        return None
    expires = job.lease_expires_at
    if not expires or (expires if expires.tzinfo else expires.replace(tzinfo=UTC)) <= datetime.now(UTC):
        return None
    return job


async def renew_job_lease(
    factory: sessionmaker[Session],
    job_id: str,
    owner: str,
    lease_seconds: int,
    stop: asyncio.Event,
) -> None:
    lease_seconds = max(lease_seconds, MIN_JOB_LEASE_SECONDS)
    interval = max(1.0, lease_seconds / 3)
    while True:
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return
        except TimeoutError:
            try:
                if not _renew_job_lease_once(factory, job_id, owner, lease_seconds):
                    return
            except SQLAlchemyError:
                logger.warning("job lease renewal failed", extra={"job_id": job_id})
                return


def _renew_job_lease_once(
    factory: sessionmaker[Session], job_id: str, owner: str, lease_seconds: int
) -> bool:
    current = datetime.now(UTC)
    with factory.begin() as db:
        job = db.scalar(
            select(ScanJob)
            .where(
                ScanJob.id == job_id,
                ScanJob.state == "LEASED",
                ScanJob.lease_owner == owner,
            )
            .with_for_update()
        )
        if not job or not job.lease_expires_at:
            return False
        expires = job.lease_expires_at
        if (expires if expires.tzinfo else expires.replace(tzinfo=UTC)) <= current:
            return False
        job.lease_expires_at = current + timedelta(
            seconds=max(lease_seconds, MIN_JOB_LEASE_SECONDS)
        )
        return True


def _web_risk_quota(provider: ProviderConfig | None) -> int | None:
    value = (
        provider.config.get("requests_per_minute", DEFAULT_WEB_RISK_QUOTA_PER_MINUTE)
        if provider
        else DEFAULT_WEB_RISK_QUOTA_PER_MINUTE
    )
    return value if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 10_000 else None


def _consume_web_risk_quota(db: Session, limit: int, now: datetime | None = None) -> bool:
    window = (now or datetime.now(UTC)).replace(second=0, microsecond=0)
    values = {
        "principal": "google_web_risk",
        "category": "provider_quota",
        "window_start": window,
        "count": 0,
    }
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        db.execute(postgresql_insert(RateLimitBucket).values(**values).on_conflict_do_nothing())
    elif dialect == "sqlite":
        db.execute(sqlite_insert(RateLimitBucket).values(**values).on_conflict_do_nothing())
    else:
        if not db.scalar(
            select(RateLimitBucket).where(
                RateLimitBucket.principal == values["principal"],
                RateLimitBucket.category == values["category"],
                RateLimitBucket.window_start == window,
            )
        ):
            db.add(RateLimitBucket(**values))
            db.flush()
    row = db.scalar(
        select(RateLimitBucket)
        .where(
            RateLimitBucket.principal == values["principal"],
            RateLimitBucket.category == values["category"],
            RateLimitBucket.window_start == window,
        )
        .with_for_update()
    )
    assert row is not None
    if row.count >= limit:
        return False
    row.count += 1
    db.flush()
    return True
