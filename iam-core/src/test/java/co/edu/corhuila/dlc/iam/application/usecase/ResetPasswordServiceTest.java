package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.PasswordResetUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class ResetPasswordServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-31T12:00:00Z");
    private static final UUID USER = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID CHALLENGE = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID CORRELATION = UUID.fromString("00000000-0000-0000-0000-000000000003");
    private final FakeStore store = new FakeStore();
    private final ResetPasswordService service = new ResetPasswordService(
        store, raw -> "token-hash:" + raw, raw -> "bcrypt:" + raw,
        Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void consumesRecoveryTokenChangesHashAndRevokesSessionsOnce() {
        service.reset("opaque-secret", "ValidPass1", CORRELATION);
        assertEquals("token-hash:opaque-secret", store.lookedUpHash);
        assertEquals("PASSWORD_RECOVERY", store.lookedUpPurpose);
        assertEquals("bcrypt:ValidPass1", store.passwordHash);
        assertEquals(USER, store.revokedUser);
        assertEquals(CORRELATION, store.correlationId);
        assertEquals(NOW, store.revokedAt);
        assertEquals(1, store.commits);
        assertThrows(InvalidRecoveryChallengeException.class,
            () -> service.reset("opaque-secret", "ValidPass1", CORRELATION));
        assertEquals(1, store.commits);
    }

    @Test
    void wrongPurposeExpiredAndUnknownChallengesHaveNoEffects() {
        store.challenge = challenge("EMAIL_VERIFICATION", NOW.plusSeconds(10), null);
        assertThrows(InvalidRecoveryChallengeException.class,
            () -> service.reset("opaque-secret", "ValidPass1", CORRELATION));
        store.challenge = challenge("PASSWORD_RECOVERY", NOW, null);
        assertThrows(InvalidRecoveryChallengeException.class,
            () -> service.reset("opaque-secret", "ValidPass1", CORRELATION));
        store.challenge = null;
        assertThrows(InvalidRecoveryChallengeException.class,
            () -> service.reset("opaque-secret", "ValidPass1", CORRELATION));
        assertEquals(0, store.passwordChanges);
        assertEquals(0, store.revocations);
    }

    @Test
    void rejectsWeakAndOversizePasswordsBeforeStorage() {
        for (String password : new String[]{"short1A", "lowercase1", "NoNumberHere",
            "ValidPass1" + "é".repeat(40)}) {
            assertThrows(IllegalArgumentException.class,
                () -> service.reset("opaque-secret", password, CORRELATION));
        }
        assertThrows(IllegalArgumentException.class,
            () -> service.reset(" ", "ValidPass1", CORRELATION));
        assertEquals(0, store.executions);
    }

    @Test
    void failedConsumptionOrPasswordWriteCannotCommit() {
        store.consumeSucceeds = false;
        assertThrows(InvalidRecoveryChallengeException.class,
            () -> service.reset("opaque-secret", "ValidPass1", CORRELATION));
        store.consumeSucceeds = true;
        store.passwordWriteSucceeds = false;
        assertThrows(InvalidRecoveryChallengeException.class,
            () -> service.reset("opaque-secret", "ValidPass1", CORRELATION));
        assertEquals(0, store.commits);
        assertEquals(0, store.revocations);
    }

    @Test
    void revocationFailureCannotCommitPasswordReset() {
        store.failRevocation = true;
        assertThrows(IllegalStateException.class,
            () -> service.reset("opaque-secret", "ValidPass1", CORRELATION));
        assertEquals(0, store.commits);
    }

    private static PasswordResetUnitOfWork.Challenge challenge(
        String purpose, Instant expiresAt, Instant consumedAt) {
        return new PasswordResetUnitOfWork.Challenge(
            CHALLENGE, USER, purpose, expiresAt, consumedAt);
    }

    private static final class FakeStore implements PasswordResetUnitOfWork,
                                                    PasswordResetUnitOfWork.Store {
        Challenge challenge = challenge("PASSWORD_RECOVERY", NOW.plusSeconds(60), null);
        boolean consumeSucceeds = true;
        boolean passwordWriteSucceeds = true;
        boolean failRevocation;
        boolean consumed;
        int executions;
        int commits;
        int passwordChanges;
        int revocations;
        String lookedUpHash;
        String lookedUpPurpose;
        String passwordHash;
        UUID revokedUser;
        UUID correlationId;
        Instant revokedAt;

        public <T> T execute(Function<Store, T> operation) {
            executions++;
            T result = operation.apply(this);
            commits++;
            return result;
        }
        public Challenge findForUpdate(String tokenHash, String purpose) {
            lookedUpHash = tokenHash;
            lookedUpPurpose = purpose;
            return consumed && challenge != null
                ? challenge(challenge.purpose(), challenge.expiresAt(), NOW) : challenge;
        }
        public boolean consume(UUID challengeId, Instant at) {
            if (!consumeSucceeds) return false;
            consumed = true;
            return true;
        }
        public boolean changePassword(UUID userId, String hash, Instant at) {
            if (!passwordWriteSucceeds) return false;
            passwordHash = hash;
            passwordChanges++;
            return true;
        }
        public void revokeSessions(UUID userId, UUID correlationId, Instant at) {
            if (failRevocation) throw new IllegalStateException("outbox failure");
            revokedUser = userId;
            this.correlationId = correlationId;
            revokedAt = at;
            revocations++;
        }
    }
}
