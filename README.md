# DLC IAM API

DLC Identity and Access Management microservice, developed with Java 21 and Spring Boot 3.5.0.

**Current status:** IAM use cases and adapters are being delivered incrementally. See each PR for its implemented scope and validation evidence.

## Project Structure

The project is organized into three Maven modules following the hexagonal architecture defined in Appendix C:

```text
dlc-iam-api/
├── .github/
│   ├── pull_request_template.md
│   └── workflows/
│       └── ci.yml
├── deploy/
│   └── .gitkeep
├── iam-core/
│   ├── pom.xml
│   └── src/
│       ├── main/java/co/edu/corhuila/dlc/iam/
│       │   ├── application/
│       │   │   ├── port/
│       │   │   │   ├── in/package-info.java
│       │   │   │   └── out/package-info.java
│       │   │   └── usecase/package-info.java
│       │   └── domain/model/package-info.java
│       └── test/java/co/edu/corhuila/dlc/iam/application/usecase/.gitkeep
├── iam-adapters/
│   ├── pom.xml
│   └── src/
│       ├── main/java/co/edu/corhuila/dlc/iam/adapter/
│       │   ├── in/http/package-info.java
│       │   └── out/persistence/package-info.java
│       └── test/java/co/edu/corhuila/dlc/iam/adapter/out/persistence/.gitkeep
├── iam-app/
│   ├── pom.xml
│   └── src/
│       ├── main/
│       │   ├── java/co/edu/corhuila/dlc/iam/app/IamApplication.java
│       │   └── resources/application.yml
│       └── test/java/co/edu/corhuila/dlc/iam/app/.gitkeep
├── .env.example
├── .gitignore
├── pom.xml
└── README.md
```

The account-lock slice records three consecutive failed passwords, locks for 15 minutes, and writes `UserLocked`/`UserUnlocked` to the owner outbox. HU-IAM-005 also requires the independent IP limit and authorized administrator unlock. Session rotation and revocation remain HU-IAM-006 work.

### Responsibility of Each Module

- **`iam-core`**: contains the domain, use cases, and input (`in`) and output (`out`) ports.
- **`iam-adapters`**: contains HTTP entry points, security, and IAM persistence adapters; it depends on `iam-core`.
- **`iam-app`**: contains `IamApplication`, the initial Spring Boot configuration, and the dependencies required to assemble the modules.

The `package-info.java` files preserve the Java packages within the project skeleton. The `.gitkeep` files allow empty test and deployment directories to be tracked by Git.

## Database and Migrations

IAM owns its data in the `iam` PostgreSQL schema. `dlc-infra-postgres` supplies the shared PostgreSQL engine, while `dlc-iam-db` owns IAM schema definitions, Liquibase changesets, and migration tooling. This repository contains the IAM API.

During normal operation, the API uses an IAM-scoped runtime role through its persistence adapters. Liquibase migrations run separately with the IAM migrator role; the API does not execute them. Set `IAM_DATABASE_URL`, `IAM_DATABASE_USER`, and `IAM_DATABASE_PASSWORD` in the environment.

## Login transport configuration

Set `IAM_REGISTRATION_PROOF_KEY_BASE64` to a separate Base64-encoded random key of at least 32 bytes. Keep it consistent across IAM instances: it proves registration request retries without persisting a raw password. Rotate it only with a coordinated plan for existing idempotency keys.

Set `IAM_AUTH_ALLOWED_ORIGIN` to the exact portal origin and `IAM_LOGIN_IP_DIGEST_KEY_BASE64` to a secret Base64-encoded key of at least 32 random bytes. The login endpoint fails startup without either value. Provision the IAM DB display-name, IP-attempt, and expired-lock-audit migrations before deploying this endpoint.

When IAM is reachable through the API Gateway, set `IAM_TRUSTED_GATEWAY_IP` to
the gateway's exact IP address as seen by the IAM container on the private
network. By default it is empty and no forwarded address is trusted. Only
requests whose direct peer matches that IP use the rightmost
`X-Forwarded-For` address appended by the gateway; all other requests use
their direct peer. Do not configure the whole Docker subnet or expose IAM
directly to untrusted clients. Keep the gateway address stable or update this
setting when the deployment changes it. Login, email verification requests,
and password recovery requests share this policy.

Set `IAM_CSRF_KEY_BASE64` to a separate Base64-encoded random key of at least 32 bytes. `GET /api/v1/auth/csrf` validates the refresh cookie against the IAM session and returns a non-cacheable, session-bound HMAC proof for cookie-backed operations. Keep this key consistent across Auth instances; rotate it as a coordinated session change.

## Internal session validation

`POST /internal/v1/sessions/validations` accepts `{ "accessToken": "..." }` and returns only `{ "active": true|false }`. Callers present a separate signed service JWT with the `identity:validate` scope. Set its trusted JWKS, issuer, and audience with `IAM_INTERNAL_SERVICE_JWKS_URI`, `IAM_INTERNAL_SERVICE_ISSUER`, and `IAM_INTERNAL_SERVICE_AUDIENCE`. Keep this route off the public Gateway.

IAM checks the staff JWT signature, issuer, audience, expiry, session revocation, account state, inactivity deadline, and current roles. Invalid staff tokens return `active: false`; a database outage returns 503 so callers can fail closed. Token bodies are not logged.

## IAM event publishing

Set `IAM_RABBITMQ_HOST`, `IAM_RABBITMQ_USER`, `IAM_RABBITMQ_PASSWORD`, and optionally `IAM_RABBITMQ_PORT` and `IAM_OUTBOX_EXCHANGE`. The IAM API declares a durable topic exchange (default `iam.events.v1`) and publishes persistent, version 1 JSON envelopes using routing keys `iam.<EventType>.v1`. The broker must have a matching durable queue binding before events can be marked published. Broker acknowledgement without a route counts as failure. Event IDs stay stable across retries; consumers must deduplicate by `eventId`.

The scheduled dispatcher checks for due events every two seconds after a five-second startup delay and processes at most 25 per tick. Set `IAM_OUTBOX_POLL_DELAY_MS` and `IAM_OUTBOX_INITIAL_DELAY_MS` to tune the cadence. It stores failed attempts and reconciliation state in IAM PostgreSQL. Publishing is at least once: broker acceptance followed by a database commit failure can cause a duplicate on retry.

## Requirements

- Java 21
- Maven compatible with Spring Boot 3.5.0

## Build

From the repository root:

```bash
mvn clean verify
```

The command above builds all three modules and runs the current IAM unit tests.

To build the API runtime image after local tests, run `docker build -t dlc-iam-api:local .` from the repository root. The image packages the Spring Boot application and runs as UID 10001. Supply IAM database, JWT, SMTP, broker, and other required environment variables from the target environment's secret store when running it; the image contains no credentials.

For Compose, select the stage, its private environment file, and the matching network explicitly. From the repository root, set `IAM_STAGE=develop`, `IAM_ENV_FILE=../.env.develop`, and `IAM_PLATFORM_NETWORK=platform` in the shell, then run `docker compose -f deploy/compose.yml config --quiet` and `docker compose -f deploy/compose.yml up -d --build`. The file path is relative to `deploy/`; keep each stage's credentials and database URL in its own ignored file. The service has no published host port, so ingress must be provided separately by the platform. Do not point a `qa` or `main` stage at the development database or network.
