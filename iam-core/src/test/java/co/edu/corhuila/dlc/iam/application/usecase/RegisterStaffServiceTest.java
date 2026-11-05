package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.RegistrationUnitOfWork;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ConcurrentModificationException;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class RegisterStaffServiceTest {
    private final UUID admin = UUID.randomUUID();
    private final UUID key = UUID.randomUUID();
    private final UUID correlation = UUID.randomUUID();
    private final FakeStore store = new FakeStore();
    private int deliveries;
    private final RegisterStaffService service = new RegisterStaffService(store, raw -> "bcrypt-hash",
        (email, password, name, role) -> (email + "|" + password + "|" + name + "|" + role)
            .getBytes(StandardCharsets.UTF_8),
        Clock.fixed(Instant.parse("2026-11-05T12:00:00Z"), ZoneOffset.UTC),
        () -> "opaque-token", raw -> "hash-of-" + raw,
        (email, token, id) -> {
            assertEquals("staff@example.test", email);
            assertEquals("opaque-token", token);
            assertEquals(true, store.committed);
            deliveries++;
        });

    @Test
    void createsPendingStaffWithNormalizedEmailAndAtomicOwnerOperations() {
        var staff = service.register(admin, " Staff@Example.Test ", "GoodPass9", "Ada Staff",
            "DENTIST", key, correlation);
        assertEquals("staff@example.test", staff.email());
        assertEquals("PENDING_VERIFICATION", staff.status());
        assertEquals(1, staff.version());
        assertEquals("bcrypt-hash", store.passwordHash);
        assertEquals(1, store.creates);
        assertEquals(1, store.audits);
        assertEquals(1, store.events);
        assertEquals(1, store.attempts);
        assertEquals(1, store.challenges);
        assertEquals("hash-of-opaque-token", store.tokenHash);
        assertEquals(1, deliveries);
    }

    @Test
    void keyedReplayHasNoAdditionalEffectsAndRejectsChangedPayload() {
        var first = service.register(admin, "staff@example.test", "GoodPass9", "Ada Staff",
            "DENTIST", key, correlation);
        var replay = service.register(admin, "STAFF@example.test", "GoodPass9", "Ada Staff",
            "DENTIST", key, UUID.randomUUID());
        assertEquals(first, replay);
        assertEquals(1, store.creates);
        assertEquals(1, store.events);
        assertEquals(1, store.challenges);
        assertEquals(1, deliveries);
        assertThrows(ConcurrentModificationException.class, () -> service.register(admin,
            "staff@example.test", "ChangedPass9", "Ada Staff", "DENTIST", key, correlation));
    }

    @Test
    void providerFailureDoesNotUndoRegistration() {
        var failing = new RegisterStaffService(store, raw -> "bcrypt-hash",
            (email, password, name, role) -> (email + "|" + password + "|" + name + "|" + role)
                .getBytes(StandardCharsets.UTF_8),
            Clock.fixed(Instant.parse("2026-11-05T12:00:00Z"), ZoneOffset.UTC),
            () -> "opaque-token", raw -> "hash-of-" + raw,
            (email, token, id) -> { throw new IllegalStateException("provider unavailable"); });
        var staff = failing.register(admin, "staff@example.test", "GoodPass9", "Ada Staff",
            "DENTIST", key, correlation);
        assertEquals("PENDING_VERIFICATION", staff.status());
        assertEquals(1, store.challenges);
        assertEquals(1, store.events);
    }

    @Test
    void rejectsDuplicateEmailAndNonAdministrator() {
        store.emailExists = true;
        assertThrows(ConcurrentModificationException.class, () -> register("DENTIST", "GoodPass9"));
        assertEquals(0, store.creates);
        store.emailExists = false;
        store.administrator = false;
        assertThrows(SecurityException.class, () -> register("DENTIST", "GoodPass9"));
        assertEquals(0, store.creates);
    }

    @Test
    void rejectsUnapprovedRolesAndPasswordsBeforeTransaction() {
        for (String role : new String[] {"ADMINISTRATOR", "PATIENT", "ASSISTANT"}) {
            assertThrows(IllegalArgumentException.class, () -> register(role, "GoodPass9"));
        }
        for (String password : new String[] {"short1A", "lowercase9", "NO_DIGITS",
            "É".repeat(40) + "Aa9"}) {
            assertThrows(IllegalArgumentException.class, () -> register("DENTIST", password));
        }
        assertEquals(0, store.transactions);
    }

    private RegistrationUnitOfWork.Staff register(String role, String password) {
        return service.register(admin, "staff@example.test", password, "Ada Staff", role,
            key, correlation);
    }

    private static final class FakeStore implements RegistrationUnitOfWork,
                                                    RegistrationUnitOfWork.Store {
        boolean administrator = true;
        boolean emailExists;
        int transactions;
        int creates;
        int audits;
        int events;
        int attempts;
        int challenges;
        String tokenHash;
        boolean committed;
        String passwordHash;
        Attempt attempt;

        @Override
        public <T> T execute(Function<Store, T> operation) {
            transactions++;
            T result = operation.apply(this);
            committed = true;
            return result;
        }

        @Override
        public boolean activeAdministratorForUpdate(UUID actorId) { return administrator; }

        @Override
        public Attempt findAttempt(UUID idempotencyKey) { return attempt; }

        @Override
        public boolean emailExists(String normalizedEmail) { return emailExists; }

        @Override
        public void createStaff(UUID userId, UUID actorId, String normalizedEmail, String hash,
                                String name, String role, Instant at) {
            creates++;
            passwordHash = hash;
        }

        @Override
        public void createVerificationChallenge(UUID challengeId, UUID userId, String hash,
                                                Instant createdAt, Instant expiresAt) {
            challenges++;
            tokenHash = hash;
            assertEquals(createdAt.plusSeconds(86400), expiresAt);
        }

        @Override
        public void appendAudit(UUID userId, UUID actorId, UUID correlationId, Instant at) { audits++; }

        @Override
        public void appendUserRegistered(UUID userId, UUID actorId, UUID correlationId, Instant at) {
            events++;
        }

        @Override
        public void rememberAttempt(UUID idempotencyKey, UUID actorId, byte[] proof, Staff staff) {
            attempts++;
            attempt = new Attempt(actorId, proof, staff);
        }
    }
}
