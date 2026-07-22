from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from phishguard.application.auth import create_guest_session
from phishguard.application.scans import ScanService, _decision_evidence_is_fresh
from phishguard.domain.types import Evidence, EvidenceState
from phishguard.infrastructure.models import (
    AnalysisRun,
    ApplicationSession,
    Decision,
    EvidenceObservation,
    IdempotencyRecord,
    ProviderConfig,
    RateLimitBucket,
    ScanJob,
)
from phishguard.infrastructure.providers import _evidence_from_fetcher
from phishguard.jobs.worker import (
    _consume_web_risk_quota,
    _owned_job,
    _renew_job_lease_once,
    cleanup_expired,
    lease_jobs,
    process_job,
)


class FakeWebRisk:
    def __init__(self):
        self.urls: list[str] = []

    async def lookup(self, url: str) -> Evidence:
        self.urls.append(url)
        return Evidence("reputation", EvidenceState.UNAVAILABLE, "google_web_risk", reason_code="fixture")


class FakeFetcher:
    def __init__(self):
        self.calls: list[tuple[str, str, str]] = []

    async def enrich(self, url: str, run_id: str, correlation_id: str) -> tuple[Evidence, ...]:
        self.calls.append((url, run_id, correlation_id))
        return (Evidence("network", EvidenceState.TIMED_OUT, "isolated_fetcher", reason_code="fixture"),)


def test_worker_strips_fragment_and_persists_partial_final(app) -> None:
    with app.state.session_factory.begin() as db:
        principal, _, _ = create_guest_session(db)
        scan, _, _ = ScanService(db, app.state.settings, app.state.cipher, None).create(
            principal, "https://example.com/path?q=1#never-disclose", "enriched", True
        )
        job = db.scalar(select(ScanJob).where(ScanJob.run_id == scan.run_id))
        ids = lease_jobs(db, "test-worker", 1, 30)
        assert ids == [job.id]
        job_id = job.id
    web_risk, fetcher = FakeWebRisk(), FakeFetcher()
    asyncio.run(process_job(app.state.session_factory, job_id, app.state.cipher, None, web_risk, fetcher))
    assert web_risk.urls == ["https://example.com/path?q=1"]
    assert fetcher.calls[0][0] == "https://example.com/path?q=1"
    with app.state.session_factory() as db:
        job = db.get(ScanJob, job_id)
        final = db.scalar(select(Decision).where(Decision.run_id == scan.run_id, Decision.stage == "FINAL"))
        evidence = list(db.scalars(select(EvidenceObservation).where(EvidenceObservation.run_id == scan.run_id)))
        assert job.state == "COMPLETE"
        assert final.completion == "PARTIAL"
        assert final.ruleset_version == "local-rules-1+enrichment-rules-1"
        assert len(evidence) == 2
        assert all(item.expires_at is None for item in evidence)
    with app.state.session_factory.begin() as db:
        _, reused, processing = ScanService(db, app.state.settings, app.state.cipher, None).create(
            principal, "https://example.com/path?q=1#never-disclose", "enriched", True
        )
        assert processing is True
        assert reused.stage == "LOCAL"


class FreshWebRisk(FakeWebRisk):
    async def lookup(self, url: str) -> Evidence:
        self.urls.append(url)
        return Evidence(
            "reputation",
            EvidenceState.NO_MATCH,
            "google_web_risk",
            version="v1",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )


class FreshFetcher(FakeFetcher):
    async def enrich(self, url: str, run_id: str, correlation_id: str) -> tuple[Evidence, ...]:
        self.calls.append((url, run_id, correlation_id))
        return tuple(
            Evidence(
                family,
                EvidenceState.NOT_APPLICABLE if family in {"tls", "static_html"} else EvidenceState.OBSERVED,
                f"isolated_fetcher:{family}",
                value={},
                version="fetcher-test-1",
            )
            for family in ("dns", "rdap", "tls", "redirect", "static_html")
        )


def test_enriched_reuse_requires_fresh_decision_pinned_evidence(app) -> None:
    url = "https://fresh.example/path"
    with app.state.session_factory.begin() as db:
        principal, _, _ = create_guest_session(db)
        scan, _, _ = ScanService(db, app.state.settings, app.state.cipher, None).create(
            principal, url, "enriched", True
        )
        job = db.scalar(select(ScanJob).where(ScanJob.run_id == scan.run_id))
        assert lease_jobs(db, "cache-worker", 1, 30) == [job.id]
        job_id = job.id

    web_risk, fetcher = FreshWebRisk(), FreshFetcher()
    asyncio.run(process_job(app.state.session_factory, job_id, app.state.cipher, None, web_risk, fetcher))
    with app.state.session_factory.begin() as db:
        fetched_rows = list(
            db.scalars(
                select(EvidenceObservation).where(
                    EvidenceObservation.run_id == scan.run_id,
                    EvidenceObservation.family != "reputation",
                )
            )
        )
        assert fetched_rows and all(row.expires_at is not None for row in fetched_rows)
        _, reused, processing = ScanService(db, app.state.settings, app.state.cipher, None).create(
            principal, url, "enriched", True
        )
        assert processing is False
        assert reused.stage == "FINAL"

        final = reused
        evidence = db.get(EvidenceObservation, final.evidence_ids[0])
        original = (evidence.state, evidence.source, evidence.version, evidence.expires_at)
        for field, value in (
            ("state", "UNAVAILABLE"),
            ("state", "TIMED_OUT"),
            ("state", "REJECTED_SAFETY"),
            ("source", ""),
            ("version", "unknown"),
            ("expires_at", datetime.now(UTC) - timedelta(seconds=1)),
        ):
            setattr(evidence, field, value)
            db.flush()
            assert _decision_evidence_is_fresh(db, final) is False
            evidence.state, evidence.source, evidence.version, evidence.expires_at = original
            db.flush()

        _, local, processing = ScanService(db, app.state.settings, app.state.cipher, None).create(
            principal, url, "local_only", False
        )
        assert processing is False
        assert local.stage == "LOCAL"
        assert local.evidence_ids == []
    assert len(web_risk.urls) == 1
    assert len(fetcher.calls) == 1


def test_web_risk_quota_is_fixed_window_and_exhaustion_does_not_fail_scan(app) -> None:
    window = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
    with app.state.session_factory.begin() as db:
        assert _consume_web_risk_quota(db, 1, window) is True
        assert _consume_web_risk_quota(db, 1, window + timedelta(seconds=30)) is False
        assert _consume_web_risk_quota(db, 1, window + timedelta(minutes=1)) is True

    with app.state.session_factory.begin() as db:
        db.query(RateLimitBucket).delete()
        db.add(ProviderConfig(provider="google_web_risk", config={"requests_per_minute": 1}))
        principal, _, _ = create_guest_session(db)
        job_ids: list[str] = []
        run_ids: list[str] = []
        for path in ("one", "two"):
            scan, _, _ = ScanService(db, app.state.settings, app.state.cipher, None).create(
                principal, f"https://quota.example/{path}", "enriched", True
            )
            job = db.scalar(select(ScanJob).where(ScanJob.run_id == scan.run_id))
            job_ids.append(job.id)
            run_ids.append(scan.run_id)
        assert set(lease_jobs(db, "quota-worker", 2, 30)) == set(job_ids)

    web_risk, fetcher = FakeWebRisk(), FakeFetcher()
    for job_id in job_ids:
        asyncio.run(process_job(app.state.session_factory, job_id, app.state.cipher, None, web_risk, fetcher))
    assert len(web_risk.urls) == 1
    assert len(fetcher.calls) == 2
    with app.state.session_factory() as db:
        assert all(db.get(ScanJob, job_id).state == "COMPLETE" for job_id in job_ids)
        second = db.scalar(
            select(EvidenceObservation).where(
                EvidenceObservation.run_id == run_ids[1],
                EvidenceObservation.family == "reputation",
            )
        )
        assert second.state == "SKIPPED_POLICY"
        assert second.reason_code == "provider_quota_exhausted"


def test_lease_has_safe_minimum_and_stale_owner_cannot_process(app) -> None:
    with app.state.session_factory.begin() as db:
        principal, _, _ = create_guest_session(db)
        scan, _, _ = ScanService(db, app.state.settings, app.state.cipher, None).create(
            principal, "https://example.com/", "enriched", True
        )
        job = db.scalar(select(ScanJob).where(ScanJob.run_id == scan.run_id))
        before = datetime.now(UTC)
        assert lease_jobs(db, "current-worker", 1, 10) == [job.id]
        job_id = job.id
        assert (job.lease_expires_at.replace(tzinfo=UTC) - before).total_seconds() >= 29

    web_risk, fetcher = FakeWebRisk(), FakeFetcher()
    asyncio.run(
        process_job(
            app.state.session_factory,
            job_id,
            app.state.cipher,
            None,
            web_risk,
            fetcher,
            "stale-worker",
        )
    )
    assert not web_risk.urls
    assert not fetcher.calls
    with app.state.session_factory() as db:
        job = db.get(ScanJob, job_id)
        assert job.state == "LEASED"
        assert job.lease_owner == "current-worker"


def test_commit_ownership_check_rejects_reassigned_or_expired_lease(app) -> None:
    with app.state.session_factory.begin() as db:
        principal, _, _ = create_guest_session(db)
        scan, _, _ = ScanService(db, app.state.settings, app.state.cipher, None).create(
            principal, "https://example.com/", "enriched", True
        )
        job = db.scalar(select(ScanJob).where(ScanJob.run_id == scan.run_id))
        assert lease_jobs(db, "first-worker", 1, 30) == [job.id]
        job_id = job.id

    with app.state.session_factory.begin() as db:
        job = db.get(ScanJob, job_id)
        job.lease_owner = "replacement-worker"
    with app.state.session_factory() as db:
        assert _owned_job(db, job_id, "first-worker") is None

    with app.state.session_factory.begin() as db:
        job = db.get(ScanJob, job_id)
        job.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with app.state.session_factory() as db:
        assert _owned_job(db, job_id, "replacement-worker") is None


def test_active_worker_can_renew_lease_without_reviving_expired_work(app) -> None:
    with app.state.session_factory.begin() as db:
        principal, _, _ = create_guest_session(db)
        scan, _, _ = ScanService(db, app.state.settings, app.state.cipher, None).create(
            principal, "https://renew.example/", "enriched", True
        )
        job = db.scalar(select(ScanJob).where(ScanJob.run_id == scan.run_id))
        assert lease_jobs(db, "renew-worker", 1, 30) == [job.id]
        job_id = job.id
        job.lease_expires_at = datetime.now(UTC) + timedelta(seconds=1)

    assert _renew_job_lease_once(app.state.session_factory, job_id, "renew-worker", 30) is True
    with app.state.session_factory() as db:
        job = db.get(ScanJob, job_id)
        expiry = job.lease_expires_at.replace(tzinfo=UTC)
        assert expiry > datetime.now(UTC) + timedelta(seconds=28)

    with app.state.session_factory.begin() as db:
        db.get(ScanJob, job_id).lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert _renew_job_lease_once(app.state.session_factory, job_id, "renew-worker", 30) is False


def test_fetcher_observation_contract_is_bounded_and_normalized() -> None:
    item = _evidence_from_fetcher(
        {
            "family": "DNS",
            "state": "OBSERVED",
            "source": "recursive-dns",
            "observed_at": "2026-07-22T12:00:00Z",
            "producer_version": "fetcher-0.1.0",
            "value": {"addresses": ["93.184.216.34"]},
        }
    )
    assert item.family == "dns"
    assert item.source == "isolated_fetcher:recursive-dns"
    assert item.version == "fetcher-0.1.0"
    assert logging.getLogger("httpx").level >= logging.WARNING
    assert logging.getLogger("httpcore").level >= logging.WARNING


def test_cleanup_removes_orphan_run_and_sensitive_derived_rows(app) -> None:
    with app.state.session_factory.begin() as db:
        principal, _, _ = create_guest_session(db)
        scan, _, _ = ScanService(db, app.state.settings, app.state.cipher, None).create(
            principal, "https://expired.example/login", "local_only", False
        )
        run_id = scan.run_id
        scan.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session = db.get(ApplicationSession, principal.session_id)
        session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.add(
            IdempotencyRecord(
                principal=principal.key,
                operation="create_scan",
                key="expired-cleanup-key",
                status_code=201,
                response={"scan": {"id": scan.id}},
                expires_at=datetime.now(UTC) - timedelta(seconds=1),
            )
        )
        db.add(
            RateLimitBucket(
                principal=principal.key,
                category="scan",
                window_start=datetime.now(UTC) - timedelta(minutes=10),
                count=1,
            )
        )
    with app.state.session_factory.begin() as db:
        assert cleanup_expired(db) == 1
    with app.state.session_factory() as db:
        assert db.get(AnalysisRun, run_id) is None
        assert not db.scalar(select(Decision).where(Decision.run_id == run_id))
        assert not db.scalar(select(IdempotencyRecord))
        assert not db.scalar(select(ApplicationSession).where(ApplicationSession.id == principal.session_id))
        assert not db.scalar(select(RateLimitBucket))
