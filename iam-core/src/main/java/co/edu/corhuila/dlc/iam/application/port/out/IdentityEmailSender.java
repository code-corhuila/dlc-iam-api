package co.edu.corhuila.dlc.iam.application.port.out;

import java.util.UUID;

/** Provider adapter: attempt delivery without persisting or logging the raw credential. */
public interface IdentityEmailSender {
    /** The adapter records its sanitized outcome. Provider failure must not expose identity. */
    void sendPasswordRecovery(String normalizedEmail, String rawToken, UUID correlationId);
}
