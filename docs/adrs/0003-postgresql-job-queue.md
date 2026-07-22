# ADR-0003: PostgreSQL job leasing

- Status: Accepted
- Date: 2026-07-22

## Context

Expected submission load is 60 per minute. A separate broker would introduce a dual-write problem and another managed dependency.

## Decision

Persist enrichment jobs in the same PostgreSQL transaction as scans. Workers claim due jobs with `FOR UPDATE SKIP LOCKED`, renewable 30-second leases, bounded attempts, and idempotent evidence writes.

## Consequences

Recovery and consistency are straightforward. Add Pub/Sub only when measured queue contention or throughput exceeds the database approach.

