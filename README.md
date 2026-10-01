# DLC IAM API

DLC Identity and Access Management microservice, developed with Java 21 and Spring Boot 3.5.0.

**Current status:** project skeleton. IAM use cases, endpoints, and persistence adapters have not yet been implemented.

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

IAM is responsible for its own data. PostgreSQL definitions and migrations are managed in the database infrastructure repository; this repository contains the IAM API.

During normal operation, IAM accesses its persistence layer through its own adapters. The Migration API is used to execute database migrations and is not part of the microservice's regular operations.

## Requirements

- Java 21
- Maven compatible with Spring Boot 3.5.0

## Build

From the repository root:

```bash
mvn clean verify
```

The command above builds all three modules. Currently, no functional IAM tests have been implemented.