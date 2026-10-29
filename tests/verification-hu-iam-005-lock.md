# HU-IAM-005 account-lock slice verification

On this branch, Java 21 `mvn -B -f pom.xml verify -q` passed: 19 tests, zero
failures or skips. The core tests cover the third failed password, denial
during the lock window, and login after expiry. `git diff --check` also passed.

The original slice commit `76025c3` recorded a PostgreSQL 17.11 run with the
IAM Liquibase changesets and the synthetic account in
`hu-iam-005-synthetic-staff.sql`. It observed lock and expiry-unlock audit and
outbox records, rollback when outbox INSERT was denied, and one lock effect
under concurrent failures. That database run has **not** been repeated on this
branch because the local Docker Linux engine is unavailable.

This slice does not cover the 10-attempts/IP limit, authorized administrator
unlock, or outbox delivery. HU-IAM-005 remains open.
