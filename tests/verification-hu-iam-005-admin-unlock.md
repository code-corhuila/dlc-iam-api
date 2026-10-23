# HU-IAM-005 administrator unlock verification

On 2026-10-23, `mvn -B -q verify` passed in the Java 21 Maven Docker image. The core tests cover authorized unlock, revoked actor and invalid target state; HTTP tests cover 200, 401 and 403 with a minimized response.

The packaged API ran against an isolated PostgreSQL 17.11 instance with all eleven IAM Liquibase changesets and synthetic staff only:

- Administrator login returned 200; unlock returned 200 and PostgreSQL showed `ACTIVE|0|1|1` (status, failures, unlock audit rows, `UserUnlocked` outbox rows).
- After revoking the administrator session, the same token returned 401. A valid Dentist session returned 403.
- Temporarily removing outbox INSERT from `iam_runtime` made unlock return 503; the account remained `LOCKED` with three failures, and audit/outbox counts stayed at one. The grant was restored.
- The authorization query uses only existing `iam_runtime` grants: shared row locks on account and session, and a read of the bootstrap Administrator role. No other schema was accessed.

The test app, database, generated keys and synthetic accounts were removed after verification. Outbox delivery and consumer deduplication are separate work; this slice does not claim the HU complete.
