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

### Responsibility of Each Module

- **`iam-core`**: contains the domain, use cases, and input (`in`) and output (`out`) ports. Currently, it only defines the base packages.
- **`iam-adapters`**: contains the HTTP entry points and output adapters for persistence. Currently, it only defines the base packages and depends on `iam-core`.
- **`iam-app`**: contains `IamApplication`, the initial Spring Boot configuration, and the dependencies required to assemble the modules.

The `package-info.java` files preserve the Java packages within the project skeleton. The `.gitkeep` files allow empty test and deployment directories to be tracked by Git.

## Database and Migrations

IAM owns its data in the `iam` PostgreSQL schema. `dlc-infra-postgres` supplies the shared PostgreSQL engine, while `dlc-iam-db` owns IAM schema definitions, Liquibase changesets, and migration tooling. This repository contains the IAM API.

During normal operation, the API uses an IAM-scoped runtime role through its persistence adapters. Liquibase migrations run separately with the IAM migrator role; the API does not execute them. Set `IAM_DATABASE_URL`, `IAM_DATABASE_USER`, and `IAM_DATABASE_PASSWORD` in the environment.

## Internal session validation

`POST /internal/v1/sessions/validations` accepts `{ "accessToken": "..." }` and returns only `{ "active": true|false }`. Callers present a separate signed service JWT with the `identity:validate` scope. Set its trusted JWKS, issuer, and audience with `IAM_INTERNAL_SERVICE_JWKS_URI`, `IAM_INTERNAL_SERVICE_ISSUER`, and `IAM_INTERNAL_SERVICE_AUDIENCE`. Keep this route off the public Gateway.

IAM checks the staff JWT signature, issuer, audience, expiry, session revocation, account state, inactivity deadline, and current roles. Invalid staff tokens return `active: false`; a database outage returns 503 so callers can fail closed. Token bodies are not logged.

## Requirements

- Java 21
- Maven compatible with Spring Boot 3.5.0

## Build

From the repository root:

```bash
mvn clean verify
```

The command above builds all three modules. Currently, no functional IAM tests have been implemented.
