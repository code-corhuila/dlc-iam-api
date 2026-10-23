# HU-IAM-005 actor authentication verification

Run `docker run --rm -v "${PWD}:/workspace" -v iam-api-m2:/root/.m2 -w /workspace maven:3.9.13-eclipse-temurin-21 mvn -B verify` from this checkout.

Result on 2026-10-23: BUILD SUCCESS; 10 core and 9 app tests passed. The new tests cover RSA signature and key rollover, invalid or expired tokens, and rejection when the current IAM session is ineligible. The actor service takes roles from the current IAM database lookup, rather than trusting role claims in a previously issued token.

The JDBC lookup requires an active, verified account and an unrevoked session whose inactivity deadline is in the future. The authorized administrator-unlock endpoint and its transactional authorization test remain for the next slice. This report does not claim HU-IAM-005 complete.
