package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;

/** Signs a service JWT with the service key, never the staff key (ADR-020). */
@FunctionalInterface
public interface ServiceTokenSigner {
    String sign(String subject, String audience, String scope, Instant issuedAt, Instant expiresAt);
}
