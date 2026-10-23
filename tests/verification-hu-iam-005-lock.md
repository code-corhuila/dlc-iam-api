# HU-IAM-005 account-lock slice verification

`mvn -B -q verify` passed in the Java 21 Maven Docker image (seven core,
three HTTP and two signing tests). The new core tests cover the third failure,
continued denial while locked and eligible login after expiry.

The packaged API ran against isolated PostgreSQL 17.11 with all eleven IAM
changesets. The test used only the synthetic account in
`hu-iam-005-synthetic-staff.sql` and a temporary 2048-bit RSA key pair.

- Three wrong passwords returned the same generic 401. A correct password
  while locked also returned 401. PostgreSQL held `LOCKED`, three failures,
  one `UserLocked` outbox row, one lock audit row and no session.
- After moving only the synthetic account's lock window into the past,
  its correct password returned 200. The row became `ACTIVE` with zero
  failures; expiry audit and `UserUnlocked` outbox rows were present.
- With outbox INSERT revoked from `iam_runtime`, a would-be third failure
  returned 503. Status remained `ACTIVE`, failures remained at two, the
  existing session stayed active and audit count did not change. The grant
  was restored immediately.
- Two concurrent wrong-password requests from two failures returned 401/401.
  Row locking produced one additional `UserLocked`; the active session was
  revoked by the existing IAM trigger.

The test container, database and temporary private key were removed. This
slice does not enforce the independent IP limit or administrator unlock, and
outbox delivery/consumer deduplication remains separate integration work.
