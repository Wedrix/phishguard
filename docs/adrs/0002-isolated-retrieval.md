# ADR-0002: Isolate target-controlled retrieval

- Status: Accepted
- Date: 2026-07-22

## Context

Fetching attacker-controlled URLs creates SSRF, rebinding, parser, decompression, and content-handling risks that do not belong in the trusted application.

## Decision

Use one credentialless fetcher image behind mTLS. Run it with gVisor, no service-account token, read-only storage, dropped capabilities, restricted egress, and bounded DNS/RDAP/TLS/redirect/static-HTML processing. Return typed observations, never response bodies.

## Consequences

The jobs command owns provider access, persistence, and fusion; the fetcher owns only hostile retrieval. Local Compose may use explicit insecure HTTP for development, but deployed configuration cannot.

