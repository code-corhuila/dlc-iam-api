package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.out.LoginAttemptLimiter;
import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class LoginServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-22T12:00:00Z");
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private final FakeStore store = new FakeStore();
    private final FakePassword passwords = new FakePassword();
    private final FakeLimiter limiter = new FakeLimiter();
    private final LoginService login = new LoginService(store, limiter, passwords,
        new RefreshCredential() {
            public String generate() { return "opaque-test-refresh"; }
            public String hash(String raw) { return "hashed-" + raw; }
        }, (staff, sid, at, expiresAt) -> "signed-test-access",
        Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void activeVerifiedStaffReceivesOnlyAccessTokenAndPublicStaffData() {
        store.account = staff("ACTIVE", NOW, List.of("DENTIST"), "Ada Dentist");

        var result = login.login("  ADA@EXAMPLE.TEST ", "correct", UUID.randomUUID(), "127.0.0.1");

        assertEquals("ada@example.test", store.emailLookup);
        assertEquals("signed-test-access", result.accessToken());
        assertEquals("opaque-test-refresh", result.refreshToken());
        assertEquals("Ada Dentist", result.user().name());
        assertEquals(5, result.user().version());
        assertEquals(1, store.resetCount);
        assertEquals(1, store.sessionCount);
        assertEquals(1, store.refreshCount);
        assertEquals(1, store.outboxCount);
        assertEquals("hashed-opaque-test-refresh", store.savedHash);
        assertEquals(NOW.plusSeconds(7 * 24 * 3600), store.inactiveAt);
    }

    @Test
    void unknownUserRunsDummyPasswordCheckAndReturnsGenericFailure() {
        assertThrows(InvalidLoginException.class,
            () -> login.login("absent@example.test", "wrong", UUID.randomUUID(), "127.0.0.1"));
        assertTrue(passwords.dummyCalled);
        assertEquals(0, store.sessionCount);
        assertEquals(1, limiter.attempts);
    }

    @Test
    void blockedIpNeverStartsCredentialLookup() {
        limiter.allowed = false;
        assertThrows(LoginRateLimitedException.class,
            () -> login.login("ada@example.test", "correct", UUID.randomUUID(), "127.0.0.1"));
        assertEquals(null, store.emailLookup);
        assertEquals(0, store.sessionCount);
    }

    @Test
    void invalidPasswordOrIneligibleStaffCannotCreateSessions() {
        for (var account : List.of(
            staff("ACTIVE", NOW, List.of("DENTIST"), "Ada Dentist"),
            staff("LOCKED", NOW, List.of("DENTIST"), "Ada Dentist"),
            staff("DISABLED", NOW, List.of("DENTIST"), "Ada Dentist"),
            staff("PENDING_VERIFICATION", null, List.of("DENTIST"), "Ada Dentist"),
            staff("ACTIVE", NOW, List.of("PATIENT"), "Ada Dentist"),
            staff("ACTIVE", NOW, List.of(), "Ada Dentist"),
            staff("ACTIVE", NOW, List.of("DENTIST"), null))) {
            store.account = account;
            String password = account.status().equals("ACTIVE")
                && account.name() != null && !account.roles().isEmpty()
                && account.roles().getFirst().equals("DENTIST") ? "wrong" : "correct";
            assertThrows(InvalidLoginException.class,
                () -> login.login("ada@example.test", password, UUID.randomUUID(), "127.0.0.1"));
        }
        assertEquals(0, store.sessionCount);
        assertEquals(0, store.refreshCount);
        assertEquals(0, store.outboxCount);
    }

    @Test
    void eventFailurePreventsAResultFromBeingIssued() {
        store.account = staff("ACTIVE", NOW, List.of("ADMINISTRATOR"), "Ada Admin");
        store.failOutbox = true;
        assertThrows(IllegalStateException.class,
            () -> login.login("ada@example.test", "correct", UUID.randomUUID(), "127.0.0.1"));
    }

    @Test
    void malformedEmailAndOversizedBcryptInputAreRejectedBeforeStorage() {
        assertThrows(IllegalArgumentException.class,
            () -> login.login("not-an-email", "correct", UUID.randomUUID(), "127.0.0.1"));
        assertThrows(IllegalArgumentException.class,
            () -> login.login("ada@example.test", "A".repeat(73), UUID.randomUUID(), "127.0.0.1"));
        assertEquals(null, store.emailLookup);
    }

    @Test
    void thirdWrongPasswordLocksAccountAndLaterCorrectPasswordStillFails() {
        store.account = staff("ACTIVE", NOW, List.of("DENTIST"), "Ada Dentist");
        for (int attempt = 0; attempt < 3; attempt++) {
            assertThrows(InvalidLoginException.class,
                () -> login.login("ada@example.test", "wrong", UUID.randomUUID(), "127.0.0.1"));
        }
        assertEquals("LOCKED", store.account.status());
        assertEquals(NOW.plusSeconds(900), store.account.lockedUntil());
        assertEquals(1, store.lockEvents);
        assertThrows(InvalidLoginException.class,
            () -> login.login("ada@example.test", "correct", UUID.randomUUID(), "127.0.0.1"));
        assertEquals(0, store.sessionCount);
    }

    @Test
    void expiredLockIsAuditedAndEligibleStaffCanSignIn() {
        store.account = new LoginUnitOfWork.StaffAccount(USER_ID, "ada@example.test",
            "Ada Dentist", "encoded-correct", "LOCKED", NOW, 3,
            NOW.minusSeconds(1), 4, List.of("DENTIST"));
        var result = login.login("ada@example.test", "correct", UUID.randomUUID(), "127.0.0.1");
        assertEquals(1, store.unlockEvents);
        assertEquals(1, store.sessionCount);
        assertEquals(6, result.user().version());
    }

    private static LoginUnitOfWork.StaffAccount staff(String status, Instant verified,
                                                       List<String> roles, String name) {
        return new LoginUnitOfWork.StaffAccount(USER_ID, "ada@example.test", name,
            "encoded-correct", status, verified,
            "LOCKED".equals(status) ? 3 : 0,
            "LOCKED".equals(status) ? NOW.plusSeconds(900) : null, 4, roles);
    }

    private static final class FakePassword implements PasswordVerifier {
        boolean dummyCalled;
        public boolean matches(String raw, String encoded) {
            return ("encoded-" + raw).equals(encoded);
        }
        public void dummyCheck(String raw) { dummyCalled = true; }
    }

    private static final class FakeLimiter implements LoginAttemptLimiter {
        boolean allowed = true;
        int attempts;
        public boolean record(String peerIp) {
            attempts++;
            return allowed;
        }
    }

    private static final class FakeStore implements LoginUnitOfWork, LoginUnitOfWork.Store {
        StaffAccount account;
        String emailLookup;
        String savedHash;
        Instant inactiveAt;
        int resetCount;
        int sessionCount;
        int refreshCount;
        int outboxCount;
        int lockEvents;
        int unlockEvents;
        boolean failOutbox;

        public <T> T execute(Function<Store, T> operation) { return operation.apply(this); }
        public StaffAccount findForUpdate(String email) {
            emailLookup = email;
            return account;
        }
        public void recordFailedPassword(StaffAccount staff, Instant at, UUID correlationId) {
            int failures = staff.failedAttempts() + 1;
            boolean locked = failures == 3;
            account = new StaffAccount(staff.id(), staff.email(), staff.name(),
                staff.passwordHash(), locked ? "LOCKED" : staff.status(),
                staff.verifiedAt(), failures, locked ? at.plusSeconds(900) : null,
                staff.version() + 1, staff.roles());
            if (locked) lockEvents++;
        }
        public StaffAccount unlockExpired(StaffAccount staff, Instant at, UUID correlationId) {
            unlockEvents++;
            account = new StaffAccount(staff.id(), staff.email(), staff.name(),
                staff.passwordHash(), "ACTIVE", staff.verifiedAt(), 0, null,
                staff.version() + 1, staff.roles());
            return account;
        }
        public void resetFailures(UUID userId, Instant at) { resetCount++; }
        public void createSession(UUID sessionId, UUID userId, String deviceId,
                                  Instant at, Instant expiry) {
            sessionCount++;
            inactiveAt = expiry;
        }
        public void createRefresh(UUID familyId, UUID sessionId, UUID credentialId,
                                  String hash, Instant at, Instant expiry) {
            refreshCount++;
            savedHash = hash;
        }
        public void appendSessionStarted(UUID eventId, UUID correlationId,
                                         UUID sessionId, UUID userId, String deviceId,
                                         Instant at, Instant expiresAt) {
            if (failOutbox) throw new IllegalStateException("outbox failed");
            outboxCount++;
        }
    }
}
