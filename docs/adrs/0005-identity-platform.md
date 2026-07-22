# ADR-0005: Delegate credentials to Identity Platform

- Status: Accepted
- Date: 2026-07-22

## Context

The application needs verified email, password recovery, and TOTP MFA but should not receive or store passwords.

## Decision

Identity Platform owns credentials, email verification, recovery, and TOTP. PhishGuard exchanges a verified ID token for an opaque, revocable application session. PostgreSQL remains authoritative for application roles and object access.

## Consequences

Password controls are assessed as provider controls. Privileged roles require verified email, TOTP, inactivity expiry, and recent reauthentication. Passkeys remain P1.

