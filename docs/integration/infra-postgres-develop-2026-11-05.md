# IAM API and shared PostgreSQL develop integration

Date: 2026-11-05 (America/Bogota). This is local `develop` evidence, not a
`qa` or `main` deployment or completion of the IAM user stories.

## Revisions and scope

- `dlc-infra-postgres` `develop`: `d54d05b` (shared PostgreSQL engine and owner
  scope checker).
- `dlc-iam-db` `develop`: `824e910` (IAM bootstrap and 17 Liquibase changesets).
- `dlc-iam-api` `develop`: `fe4b72e` (API, JDBC adapters and container image).
- The existing shared engine was used at `dlc-postgres:5432/di_lucca` on the
  external `platform` network. It was healthy and initially had no `iam` schema.
- No other owner schema was created or modified by this check.

## Local execution and observed results

1. Applied `dlc-iam-db/deploy/bootstrap.sql` as the PostgreSQL bootstrap
   administrator. It created `iam_migrator`, `iam_runtime` and the `iam` schema.
   The schema owner is `iam_migrator`; runtime does not receive the bootstrap
   administrator credential.
2. Generated separate random local passwords for the two IAM roles in ignored
   secret files. Ran the IAM Liquibase Compose runner with the migrator role.
   The update applied 17 changesets, and `liquibase validate` reported no
   validation errors. The `iam` schema contained 15 tables.
3. Ran `dlc-infra-postgres/scripts/check-owner-scope.sh` over the `platform`
   network with `iam_runtime`. Result: `Owner runtime scope check passed for iam`.
   The checker rejects schema creation and access to another existing owner
   schema. At test time, the other three owner schemas did not yet exist, so
   their cross-owner denial was not exercised against live schemas.
4. Built the API image from the API revision above and started it temporarily
   on the `platform` network using `iam_runtime`. Spring Boot started; Hikari
   established PostgreSQL connections. `GET /api/v1/auth/jwks` returned 200.
   `POST /api/v1/auth/login` with a nonexistent test account returned a generic
   401 and an `X-Correlation-Id` header. PostgreSQL showed 10 connections under
   `iam_runtime` during the check.

## Remaining integration work

- The HTTP check used a temporary local RabbitMQ container. A platform broker,
  durable consumer queue bindings and stage secrets are required for a lasting
  deployment. This check did not exercise cross-service event consumption.
- No real staff account was provisioned, so successful login and session
  issuance against this shared instance remain unverified.
- SMTP delivery was not part of this PostgreSQL check. The current network
  timed out connecting to Gmail on port 587 before authentication.
- `qa` and `main` need their own database instances, credentials, keys and
  network configuration; this `develop` evidence must not be reused as their
  validation.
