package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.EmailVerificationUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class VerifyStaffEmailServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-26T14:00:00Z");
    private static final UUID USER = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID CHALLENGE = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID CORRELATION = UUID.fromString("00000000-0000-0000-0000-000000000003");
    private final FakeStore store = new FakeStore();
    private final VerifyStaffEmailService service = new VerifyStaffEmailService(
        store, raw -> "hash:" + raw, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void consumesVerificationChallengeAndActivatesStaffOnce() {
        service.verify("opaque-secret", CORRELATION);

        assertEquals("hash:opaque-secret", store.lookedUpHash);
        assertEquals("EMAIL_VERIFICATION", store.lookedUpPurpose);
        assertEquals(1, store.activations);
        assertEquals(1, store.events);
        assertEquals(USER, store.eventUser);
        assertEquals(CORRELATION, store.eventCorrelation);
        assertEquals(NOW, store.eventTime);

        assertThrows(InvalidVerificationChallengeException.class,
            () -> service.verify("opaque-secret", CORRELATION));
        assertEquals(1, store.events);
    }

    @Test
    void invalidPurposeExpiredAndUnknownTokensNeverActivate() {
        store.challenge = challenge("PASSWORD_RECOVERY", NOW.plusSeconds(10), null);
        assertThrows(InvalidVerificationChallengeException.class,
            () -> service.verify("opaque-secret", CORRELATION));
        store.challenge = challenge("EMAIL_VERIFICATION", NOW, null);
        assertThrows(InvalidVerificationChallengeException.class,
            () -> service.verify("opaque-secret", CORRELATION));
        store.challenge = null;
        assertThrows(InvalidVerificationChallengeException.class,
            () -> service.verify("opaque-secret", CORRELATION));
        assertEquals(0, store.activations);
        assertEquals(0, store.events);
    }

    @Test
    void rejectsMalformedInputBeforeHashingOrStorage() {
        assertThrows(IllegalArgumentException.class,
            () -> service.verify(" ", CORRELATION));
        assertThrows(IllegalArgumentException.class,
            () -> service.verify("x".repeat(513), CORRELATION));
        assertThrows(IllegalArgumentException.class,
            () -> service.verify("opaque-secret", null));
        assertEquals(0, store.executions);
    }

    @Test
    void ineligibleAccountAndConcurrentConsumptionFailWithoutSuccess() {
        store.eligible = false;
        assertThrows(InvalidVerificationChallengeException.class,
            () -> service.verify("opaque-secret", CORRELATION));
        assertEquals(0, store.committedTransactions);
        store.eligible = true;
        store.consumed = false;
        store.consumedByAnotherTransaction = true;
        assertThrows(InvalidVerificationChallengeException.class,
            () -> service.verify("opaque-secret", CORRELATION));
        assertEquals(0, store.committedTransactions);
        assertEquals(0, store.events);
    }

    @Test
    void outboxFailureFailsTransaction() {
        store.failOutbox = true;
        assertThrows(IllegalStateException.class,
            () -> service.verify("opaque-secret", CORRELATION));
        assertEquals(0, store.committedTransactions);
    }

    private static EmailVerificationUnitOfWork.Challenge challenge(
        String purpose, Instant expiresAt, Instant consumedAt) {
        return new EmailVerificationUnitOfWork.Challenge(
            CHALLENGE, USER, purpose, expiresAt, consumedAt);
    }

    private static final class FakeStore implements EmailVerificationUnitOfWork,
                                                    EmailVerificationUnitOfWork.Store {
        Challenge challenge = challenge("EMAIL_VERIFICATION", NOW.plusSeconds(60), null);
        boolean eligible = true;
        boolean consumedByAnotherTransaction;
        boolean failOutbox;
        boolean consumed;
        int executions;
        int committedTransactions;
        int activations;
        int events;
        String lookedUpHash;
        String lookedUpPurpose;
        UUID eventUser;
        UUID eventCorrelation;
        Instant eventTime;

        public <T> T execute(Function<Store, T> operation) {
            executions++;
            T result = operation.apply(this);
            committedTransactions++;
            return result;
        }
        public Challenge findForUpdate(String tokenHash, String purpose) {
            lookedUpHash = tokenHash;
            lookedUpPurpose = purpose;
            if (consumed && challenge != null) {
                return challenge(challenge.purpose(), challenge.expiresAt(), NOW);
            }
            return challenge;
        }
        public boolean consume(UUID challengeId, Instant at) {
            if (consumedByAnotherTransaction) return false;
            consumed = true;
            return true;
        }
        public boolean activatePendingUser(UUID userId, Instant at) {
            if (!eligible) return false;
            activations++;
            return true;
        }
        public void appendUserEmailVerified(UUID eventId, UUID userId,
                                            UUID correlationId, Instant at) {
            if (failOutbox) throw new IllegalStateException("outbox failure");
            eventUser = userId;
            eventCorrelation = correlationId;
            eventTime = at;
            events++;
        }
    }
}
