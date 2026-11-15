package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.LogoutUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class CookieCsrfProofServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-04T12:00:00Z");
    private static final RefreshCredential HASH = new RefreshCredential() {
        public String generate() { return "unused"; }
        public String hash(String raw) { return "hash:" + raw; }
    };

    @Test
    void proofIsSessionBoundAndTamperingFails() {
        UUID session = UUID.randomUUID();
        var service = service(session, null, null, null);
        String proof = service.issue("refresh-secret");
        assertFalse(proof.contains("refresh-secret"));
        service.verify("refresh-secret", proof, false);
        assertThrows(SecurityException.class,
            () -> service.verify("refresh-secret", proof + "x", false));
        assertThrows(SecurityException.class,
            () -> service(UUID.randomUUID(), null, null, null)
                .verify("refresh-secret", proof, false));
    }

    @Test
    void consumedCredentialCannotIssueButCanReachReuseDetection() {
        UUID session = UUID.randomUUID();
        String proof = service(session, null, null, null).issue("refresh-secret");
        var consumed = service(session, NOW.minusSeconds(1), null, null);
        assertThrows(InvalidLoginException.class, () -> consumed.issue("refresh-secret"));
        consumed.verify("refresh-secret", proof, true);
        assertThrows(InvalidLoginException.class,
            () -> consumed.verify("refresh-secret", proof, false));
    }

    @Test
    void revokedAndExpiredSessionsCannotIssueProofs() {
        assertThrows(InvalidLoginException.class,
            () -> service(UUID.randomUUID(), null, NOW.minusSeconds(1), null)
                .issue("refresh-secret"));
        assertThrows(InvalidLoginException.class,
            () -> service(UUID.randomUUID(), null, null, NOW.minusSeconds(1))
                .issue("refresh-secret"));
        assertThrows(IllegalArgumentException.class,
            () -> new CookieCsrfProofService(store(UUID.randomUUID(), null, null, null),
                HASH, new byte[16], Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom()));
    }

    private static CookieCsrfProofService service(UUID session, Instant consumed,
                                                  Instant revoked, Instant inactive) {
        return new CookieCsrfProofService(store(session, consumed, revoked, inactive),
            HASH, new byte[32], Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom());
    }

    private static LogoutUnitOfWork store(UUID session, Instant consumed,
                                          Instant revoked, Instant inactive) {
        return new LogoutUnitOfWork() {
            public <T> T execute(Function<Store, T> operation) {
                return operation.apply(new Store() {
                    public Credential findForUpdate(String hash) {
                        if (!hash.equals("hash:refresh-secret")) return null;
                        return new Credential(UUID.randomUUID(), session, NOW.plusSeconds(60),
                            consumed, revoked, null, null,
                            inactive == null ? NOW.plusSeconds(60) : inactive);
                    }
                    public List<UUID> activeSessionsForUpdate(UUID user, UUID current,
                                                              boolean all) { throw new AssertionError(); }
                    public boolean revokeSession(UUID user, UUID id, Instant at) {
                        throw new AssertionError();
                    }
                    public void appendSessionRevoked(UUID event, UUID user, UUID id,
                                                     UUID correlation, Instant at) {
                        throw new AssertionError();
                    }
                });
            }
        };
    }
}
