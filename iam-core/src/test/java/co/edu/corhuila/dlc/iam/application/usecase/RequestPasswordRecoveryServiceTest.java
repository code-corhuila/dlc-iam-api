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
    private boolean deliveryFails;
    private int generated;
    private final RequestPasswordRecoveryService service = new RequestPasswordRecoveryService(
        new RecoveryRequestUnitOfWork() {
            @Override public <T> T execute(Function<RecoveryRequestUnitOfWork.Store, T> action) {
                store.inTransaction = true;
                try {
                    return action.apply(store);
                } finally {
                    store.inTransaction = false;
                }
            }
        }, (requester, email) -> permitted,
        () -> { generated++; return "random-opaque-token"; },
        raw -> "sha256:" + raw,
        (email, token, correlation) -> {
            store.deliveredDuringTransaction = store.inTransaction;
            if (deliveryFails) throw new IllegalStateException("provider unavailable");
            store.deliveredToken = token;
        }, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(15));

    @Test
    void knownVerifiedAccountCommitsHashBeforeDirectDelivery() {
        store.user = UUID.randomUUID();
        service.request("  ADA@Example.Test  ", "requester", UUID.randomUUID());
        assertEquals("ada@example.test", store.lookedUpEmail);
        assertEquals("PASSWORD_RECOVERY", store.purpose);
        assertEquals("sha256:random-opaque-token", store.savedHash);
        assertEquals(NOW.plus(Duration.ofMinutes(15)), store.expiresAt);
        assertEquals("random-opaque-token", store.deliveredToken);
        assertEquals(false, store.deliveredDuringTransaction);
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
    void providerFailureRetainsNeutralResultAndCommittedChallenge() {
        store.user = UUID.randomUUID();
        deliveryFails = true;
        service.request("ada@example.test", "requester", UUID.randomUUID());
        assertEquals("sha256:random-opaque-token", store.savedHash);
        assertEquals(null, store.deliveredToken);
        assertEquals(false, store.deliveredDuringTransaction);
    }

    @Test
    void failedChallengeTransactionNeverCallsProvider() {
        store.user = UUID.randomUUID();
        store.persistenceFails = true;
        assertThrows(IllegalStateException.class,
            () -> service.request("ada@example.test", "requester", UUID.randomUUID()));
        assertEquals(null, store.deliveredToken);
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
        boolean inTransaction;
        boolean deliveredDuringTransaction;
        boolean persistenceFails;

        @Override public UUID verifiedUserForUpdate(String email) {
            lookedUpEmail = email;
            return user;
        }

        @Override public void createChallenge(UUID challengeId, UUID userId, String intendedPurpose,
                String tokenHash, Instant createdAt, Instant deadline) {
            purpose = intendedPurpose;
            if (persistenceFails) throw new IllegalStateException("database unavailable");
            savedHash = tokenHash;
            expiresAt = deadline;
        }
    }
}
