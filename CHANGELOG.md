# Changelog

Notable changes to `dlc-iam-api` are recorded here.

## [3.0.0] - 2026-11-14

First release of the IAM API to `main`, promoted from `qa` for MVP 3.

### Added

- Staff registration by an administrator with an initial email verification challenge, single-use verification and keyed replay protection (`Idempotency-Key` with an HMAC request proof).
- Staff login with bcrypt passwords, account lock after repeated failures, an atomic per-IP attempt window and audited administrative unlock.
- RS256 access tokens, public signing keys (JWKS), cookie-protected refresh with atomic rotation and reuse detection, cookie-protected logout and a session-bound CSRF proof.
- Own-session listing and revocation, and session validation for owner services so revoked sessions are rejected.
- Password recovery with neutral responses, shared request limits and single-use reset that revokes existing sessions.
- Audited staff enabling, disabling, name updates and role replacement, with session revocation where the policy requires it.
- Service JWTs by client credentials (ADR-020), staff state and role validation for owner services and the active dentist list for scheduling.
- Patients and Clinical JWT permissions, including administrator clinical read by role (ADR-019).
- Transactional outbox with confirmed, bounded delivery to RabbitMQ.
- Branded Spanish HTML and plain-text emails for verification and recovery codes over a configurable SMTP transport.
- Non-root runtime image and stage-scoped Compose runtime.

### Security

- Client IP for limits is taken only from the trusted Gateway address; forwarded headers are not rewritten automatically.
- Current JWT permission claims are validated and old sessions are denied after role changes.
- SMTP secrets are read from the git-ignored `.env`; delivery errors log the failure type and correlation id without addresses or codes.
