package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.RecoveryRequestUnitOfWork;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class RequestPasswordRecoveryServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-05T12:00:00Z");
    private final Store store = new Store();
    private boolean permitted = true;
    private int generated;
    private final RequestPasswordRecoveryService service = new RequestPasswordRecoveryService(
        new RecoveryRequestUnitOfWork() {
            @Override public <T> T execute(Function<RecoveryRequestUnitOfWork.Store, T> action) {
                return action.apply(store);
            }
        }, (requester, email) -> permitted,
        () -> { generated++; return "random-opaque-token"; },
        raw -> "sha256:" + raw,
        Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(20));

    @Test
    void knownVerifiedAccountCreatesOnlyHashedPurposeBoundChallengeAndQueuesDelivery() {
        store.user = UUID.randomUUID();
        service.request("  ADA@Example.Test  ", "requester", UUID.randomUUID());
        assertEquals("ada@example.test", store.lookedUpEmail);
        assertEquals("PASSWORD_RECOVERY", store.purpose);
        assertEquals("sha256:random-opaque-token", store.savedHash);
        assertEquals(NOW.plus(Duration.ofMinutes(20)), store.expiresAt);
        assertEquals("random-opaque-token", store.deliveredToken);
        assertEquals(1, generated);
    }

    @Test
    void unknownAccountHasSameSuccessfulOutcomeWithoutCreatingOrDeliveringToken() {
        service.request("missing@example.test", "requester", UUID.randomUUID());
        assertEquals("missing@example.test", store.lookedUpEmail);
        assertEquals(null, store.savedHash);
        assertEquals(null, store.deliveredToken);
        assertEquals(0, generated);
    }

    @Test
    void limiterAppliesBeforeAnyAccountLookup() {
        permitted = false;
        assertThrows(RecoveryRateLimitedException.class,
            () -> service.request("missing@example.test", "requester", UUID.randomUUID()));
        assertEquals(null, store.lookedUpEmail);
    }

    @Test
    void rejectsMalformedRequestsWithoutLookup() {
        assertThrows(IllegalArgumentException.class,
            () -> service.request("not-an-email", "requester", UUID.randomUUID()));
        assertThrows(IllegalArgumentException.class,
            () -> service.request("staff@example.test", " ", UUID.randomUUID()));
        assertEquals(null, store.lookedUpEmail);
    }

    private static final class Store implements RecoveryRequestUnitOfWork.Store {
        UUID user;
        String lookedUpEmail;
        String purpose;
        String savedHash;
        String deliveredToken;
        Instant expiresAt;

        @Override public UUID verifiedUserForUpdate(String email) {
            lookedUpEmail = email;
            return user;
        }

        @Override public void createChallenge(UUID challengeId, UUID userId, String intendedPurpose,
                String tokenHash, Instant createdAt, Instant deadline) {
            purpose = intendedPurpose;
            savedHash = tokenHash;
            expiresAt = deadline;
        }

        @Override public void queueDelivery(UUID userId, String email, String rawToken,
                UUID correlationId) {
            deliveredToken = rawToken;
        }
    }
}
