# HU-IAM-001 login verification

Scope: owner login and JWKS only. The full HU remains dependent on account
protection, refresh/session lifecycle and cross-repository integration.

## Automated checks

`mvn -B verify` in `maven:3.9.13-eclipse-temurin-21` passed. Surefire:

| Suite | Tests | Errors | Failures |
|---|---:|---:|---:|
| `LoginServiceTest` | 5 | 0 | 0 |
| `LoginControllerTest` | 3 | 0 | 0 |
| `RsaAccessTokenIssuerTest` | 2 | 0 | 0 |

The first download attempt failed on truncated Maven Central transfers;
retrying with a persistent Docker cache completed successfully.

## Isolated PostgreSQL and HTTP checks

Ran the built JAR on the isolated `iam-staff-name-empty` Docker network against
PostgreSQL 17.11 with all nine IAM change sets, including the additive staff
display-name migration. Synthetic accounts and a temporary RSA key pair were
used; no real credential or private key was committed.

- Active verified Dentist: HTTP 200; one-hour access token, public `Staff`
  fields and a refresh cookie marked Secure, HttpOnly, SameSite=Strict and
  scoped to `/api/v1/auth`. Response used `Cache-Control: no-store` and did
  not contain the refresh credential in JSON.
- Wrong password, unverified account and unknown account: identical
  `401 UNAUTHORIZED` body and message.
- JWKS: one RSA public key with `kid`, `n` and `e`; the issued JWT verified
  against that key with RS256. Claims included subject, session ID, approved
  role, issuer/audience, `jti` and a 3600-second lifetime, without password
  or refresh material.
- After one successful login, PostgreSQL contained exactly one owner session,
  refresh family, hashed refresh credential and `SessionStarted` outbox row.
  The event payload carried session/user/device/time identifiers, not a
  password.
- A separate API container pointed at an unavailable database host returned
  `503 SERVICE_UNAVAILABLE` with no internal hostname or JDBC details and
  `Cache-Control: no-store`.
- Revoking `iam_runtime` INSERT on `iam.outbox_events` in the isolated database
  made login return 503. Session, refresh credential and outbox counts stayed
  `2/2/2` before and after the failed request, demonstrating rollback. The
  grant was restored immediately after the check.

No host PostgreSQL port was published. The temporary test containers and key
files were removed after validation.

## Remaining integration

Account failure counting, 15-minute lock and IP throttling belong to
HU-IAM-005. Refresh rotation, CSRF, logout, session inspection and current
eligibility checks belong to HU-IAM-006. The outbox publisher and consumers
need delivery/deduplication evidence. A legacy account without
`iam.users.display_name` needs owner backfill before its login can return the
required `Staff.name`; the API rejects that state generically.
