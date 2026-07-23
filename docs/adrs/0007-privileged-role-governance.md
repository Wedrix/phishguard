# ADR-0007: Canonical administration and governed role appointment

- Status: Accepted
- Date: 2026-07-23

## Context

PhishGuard needs a recoverable root of application authority, enough delegation for the demo to be operable, and a route for registered users to request Analyst or Researcher access. Treating a registration choice as authority would permit self-escalation. Conversely, allowing every Administrator to modify every other Administrator would make the root account vulnerable to accidental lockout or a compromised delegate.

Identity Platform proves identity, verified email, and TOTP possession; it does not grant PhishGuard roles. PostgreSQL remains the authority for application roles and their governance history.

## Decision

Maintain exactly one **canonical Administrator**:

- The canonical account is created or designated only by an authenticated operator command after the account has signed in and is active, email-verified, and TOTP-verified.
- Database constraints enforce at most one canonical account and require that account to have the `ADMINISTRATOR` role.
- The canonical account cannot be disabled, demoted, or otherwise changed through an in-application user-management request.
- Canonical transfer is an explicit operator-only, atomic operation that looks up the current and successor accounts by their Identity Platform subjects and requires a confirmation flag. Subjects are excluded from audit detail and application logs. The successor is rechecked as active, email-verified, and TOTP-verified before becoming canonical Administrator; the former canonical account is demoted to `REGISTERED_USER` and disabled; sessions for both accounts are revoked; and the transition is appended to the audit chain.

Allow **delegated, non-canonical Administrators**:

- Any active Administrator may appoint an existing active, email-verified, TOTP-verified account as a non-canonical Administrator.
- Only the canonical Administrator may disable or demote a current non-canonical Administrator. Administrators cannot manage their own account through this path.
- Appointment, demotion, disablement, and re-enablement require server-side authorization, CSRF validation, recent reauthentication, an idempotency key, target revalidation, target-session revocation when authority changes, and a chained audit event.

Treat a requested role as a **request, never a grant**:

- A registered user may request `ANALYST` or `RESEARCHER`; neither the client nor the session-exchange payload can assign that role.
- A request follows the closed states `PENDING`, `APPROVED`, `REJECTED`, and `CANCELLED`. The requester may cancel a pending request; an Administrator may approve or reject it.
- Approval rechecks the target account and privileged-assurance conditions, assigns the requested role, revokes the target's existing sessions, and records the decision in the audit chain. Rejection and cancellation do not change authority.
- Role and object checks remain server-side. Hiding a control or route in the interface is usability, not an authorization control.

Audit events use stable, URL-free object identifiers and correlation IDs. Optional decision notes are bounded governance text and must not contain submitted URLs, secrets, identity-provider tokens, or unnecessary personal information. Role-request and audit records are retained as governance evidence under the documented privacy and retention limits.

## Controlled baseline change

This decision replaces the earlier v1 restriction that no in-application Administrator grant existed. It does not change ADR-0005's delegation of credentials to Identity Platform or PostgreSQL's authority over roles. The change introduces a protected canonical account, bounded delegated appointments, and an explicit approval workflow rather than unrestricted role editing.

## Consequences

The system can delegate routine administration without exposing the canonical account for every task, while operator-only transfer preserves a distinct recovery and succession boundary. A user cannot gain a privileged role merely by selecting it during registration.

The demo still has no two-person approval, expiring elevation, or independent break-glass authority. A compromised Administrator can approve Analyst/Researcher access or appoint another non-canonical Administrator; the canonical account can subsequently revoke that authority, and the audit chain supports investigation, but does not prevent the initial act. This deliberate limit is tracked in the debt register and must be reconsidered before institutional production use.
