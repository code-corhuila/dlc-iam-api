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

Set `IAM_AUTH_ALLOWED_ORIGIN` to the exact portal origin and `IAM_LOGIN_IP_DIGEST_KEY_BASE64` to a secret Base64-encoded key of at least 32 random bytes. The login endpoint fails startup without either value. It uses the direct connection peer for its per-IP window; forwarded address headers are ignored until a trusted proxy policy is implemented. Provision the IAM DB display-name, IP-attempt, and expired-lock-audit migrations before deploying this endpoint.

Set `IAM_CSRF_KEY_BASE64` to a separate Base64-encoded random key of at least 32 bytes. `GET /api/v1/auth/csrf` validates the refresh cookie against the IAM session and returns a non-cacheable, session-bound HMAC proof for cookie-backed operations. Keep this key consistent across Auth instances; rotate it as a coordinated session change.

## Internal session validation

`POST /internal/v1/sessions/validations` accepts `{ "accessToken": "..." }` and returns only `{ "active": true|false }`. Callers present a separate signed service JWT with the `identity:validate` scope. Set its trusted JWKS, issuer, and audience with `IAM_INTERNAL_SERVICE_JWKS_URI`, `IAM_INTERNAL_SERVICE_ISSUER`, and `IAM_INTERNAL_SERVICE_AUDIENCE`. Keep this route off the public Gateway.

IAM checks the staff JWT signature, issuer, audience, expiry, session revocation, account state, inactivity deadline, and current roles. Invalid staff tokens return `active: false`; a database outage returns 503 so callers can fail closed. Token bodies are not logged.

## IAM event publishing

Set `IAM_RABBITMQ_HOST`, `IAM_RABBITMQ_USER`, `IAM_RABBITMQ_PASSWORD`, and optionally `IAM_RABBITMQ_PORT` and `IAM_OUTBOX_EXCHANGE`. The IAM API declares a durable topic exchange (default `iam.events.v1`) and publishes persistent, version 1 JSON envelopes using routing keys `iam.<EventType>.v1`. The broker must have a matching durable queue binding before events can be marked published. Broker acknowledgement without a route counts as failure. Event IDs stay stable across retries; consumers must deduplicate by `eventId`.

The outbox dispatcher stores failed attempts and reconciliation state in IAM PostgreSQL. Publishing is at least once: broker acceptance followed by a database commit failure can cause a duplicate on retry. The scheduler that invokes the dispatcher is delivered separately.

## Requirements

- Java 21
- Maven compatible with Spring Boot 3.5.0

## Build

From the repository root:

```bash
mvn clean verify
```

The command above builds all three modules and runs the current IAM unit tests.
