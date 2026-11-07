package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.application.port.out.VerificationRequestUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class RequestEmailVerificationServiceTest {
    private static final UUID USER = UUID.randomUUID();
    private final AtomicBoolean committed = new AtomicBoolean();
    private final AtomicBoolean delivered = new AtomicBoolean();
    private boolean known = true;
    private boolean allowed = true;
    private final VerificationRequestUnitOfWork unitOfWork = new VerificationRequestUnitOfWork() {
        @Override
        public <T> T execute(java.util.function.Function<Store, T> operation) {
            T result = operation.apply(new Store() {
                @Override
                public UUID pendingUserForUpdate(String email) {
                    assertEquals("staff@example.test", email);
                    return known ? USER : null;
                }

                @Override
                public void replaceChallenge(UUID id, UUID userId, String hash,
                                             Instant created, Instant expires) {
                    assertEquals(USER, userId);
                    assertEquals("hash-of-token", hash);
                    assertEquals(Instant.parse("2026-11-05T00:00:00Z"), created);
                    assertEquals(created.plusSeconds(86400), expires);
                }
            });
            committed.set(true);
            return result;
        }
    };
    private final RequestEmailVerificationService service = new RequestEmailVerificationService(
        unitOfWork, (ip, email) -> allowed, () -> "token", token -> "hash-of-" + token,
        (email, token, correlation) -> {
            assertTrue(committed.get());
            assertEquals("token", token);
            delivered.set(true);
        }, Clock.fixed(Instant.parse("2026-11-05T00:00:00Z"), ZoneOffset.UTC));

    @Test
    void sendsOnlyAfterHashCommitForPendingAccount() {
        service.request(" Staff@Example.Test ", "127.0.0.1", UUID.randomUUID());
        assertTrue(delivered.get());
    }

    @Test
    void unknownAccountAndRateLimitDoNotIssueToken() {
        known = false;
        service.request("staff@example.test", "127.0.0.1", UUID.randomUUID());
        assertTrue(committed.get());
        assertEquals(false, delivered.get());
        allowed = false;
        assertThrows(RecoveryRateLimitedException.class,
            () -> service.request("staff@example.test", "127.0.0.1", UUID.randomUUID()));
    }
}
