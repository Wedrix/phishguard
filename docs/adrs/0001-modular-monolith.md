# ADR-0001: Modular monolith

- Status: Accepted
- Date: 2026-07-22

## Context

The capstone needs coherent transactions, traceability, and reproducible model evaluation at modest load. Splitting trusted domain functions into network services would add distributed failure modes without a demonstrated scaling need.

## Decision

Use one Python package and application image with `web`, `jobs`, `migrate`, `cleanup`, and `evaluate` commands. Keep domain policy independent from FastAPI, SQLAlchemy, providers, and Google SDKs. Model inference remains in-process.

## Consequences

Deployments and transactions remain simple. Commands can scale independently in Kubernetes. A new service is justified only by an incompatible trust boundary or measured scaling constraint.

