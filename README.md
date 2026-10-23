# DLC IAM API

Java 21 and Spring Boot 3.5.0 implementation of the IAM owner service. The
three Maven modules keep application rules (`iam-core`), HTTP/PostgreSQL/key
adapters (`iam-adapters`), and assembly (`iam-app`) separate.

## HU-IAM-001 login slice

`POST /api/v1/auth/login` validates a staff password and requires an active,
verified account with at least one approved internal role and a persisted
display name. It creates an IAM session, one refresh family and hashed refresh
credential, and a `SessionStarted` outbox row in one PostgreSQL transaction.
The response contains a one-hour RS256 access token and public staff fields;
the seven-day opaque refresh credential is sent only in a Secure, HttpOnly,
SameSite=Strict cookie. Invalid credentials and ineligible accounts receive the
same generic 401. `GET /api/v1/auth/jwks` publishes only the configured public
RSA key. No MFA challenge is issued under ADR-016.

The API connects as `iam_runtime` and reads/writes only the `iam` schema.
`dlc-infra-postgres` supplies the engine. `dlc-iam-db` owns Liquibase migrations
and the separate `iam_migrator` role; the API never runs migrations. Apply the
`dlc-iam-db` staff display-name migration before this API revision. Existing
rows with a missing name require an owner-reviewed backfill; login rejects them
without inventing a name.

This slice adds three-failure account locking, 15-minute expiry, and
`UserLocked`/`UserUnlocked` outbox records. HU-IAM-005 still requires the
independent 10-attempts/IP limit and authorized administrator unlock.
HU-IAM-006 supplies refresh
rotation, CSRF, logout, session inspection/revocation and current-session
eligibility checks. Outbox delivery and consumer deduplication also require
integration evidence. Until those changes are integrated, do not treat this
login endpoint as a complete deployable authentication flow.

## Configuration

Provide the variables listed in `.env.example` through the deployment secret
mechanism. `IAM_DATABASE_USER` must be `iam_runtime` or an equivalently scoped
role; never use the migrator or bootstrap account. The private key must be an
RSA PKCS#8 PEM and the public key an X.509 PEM. `IAM_JWT_KID`, issuer and
audience must match the verifier allowlist. No key or password is committed.

The `iam` database schema must already exist. HTTP routes use the gateway
relative `/api/v1/auth` prefix. The browser login contract expects HTTPS so
the Secure refresh cookie can be stored; key rotation must retain old public
keys until previously issued one-hour access tokens expire.
The optional `IAM_JWT_PREVIOUS_JWKS_JSON` supplies public-only old RSA JWKs
during that overlap. Each must have only `kty`, `kid`, `use`, `alg`, `n` and `e`;
duplicate key IDs or private fields stop startup.

## Verification

From the repository root run `mvn -B verify`, or use a Java 21 Maven image with
the repository mounted at `/workspace`. The core tests cover successful login,
unknown users, wrong passwords, ineligible status/role/name and outbox failure.
The HTTP tests cover the response, cookie, generic 401, unavailable database
and public JWKS shape. Database transaction and deployed key/cookie integration
require a PostgreSQL-backed check before promotion.
The isolated PostgreSQL-backed results for this revision are in
[`tests/verification-hu-iam-001.md`](tests/verification-hu-iam-001.md).
