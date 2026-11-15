package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.DisableStaffUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class DisableStaffAccountServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-04T12:00:00Z");
    private final UUID actor = UUID.randomUUID();
    private final UUID staff = UUID.randomUUID();
    private final UUID session = UUID.randomUUID();
    private final UUID key = UUID.randomUUID();
    private final UUID correlation = UUID.randomUUID();
    private final FakeStore store = new FakeStore();
    private final DisableStaffAccountService service = new DisableStaffAccountService(
        store, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void disablesAndRecordsOneEventPerAffectedSession() {
        var result = service.disable(actor, staff, 1, "Employment ended", key, correlation);
        assertEquals("DISABLED", result.status());
        assertEquals(2, result.version());
        assertEquals(1, store.disables);
        assertEquals(1, store.audits);
        assertEquals(List.of(session), store.revoked);
        assertEquals(correlation, store.auditCorrelation);
        assertEquals(NOW, store.auditTime);
        assertEquals(1, store.commits);
    }

    @Test
    void exactRetryReturnsOriginalVersionWithoutAnotherWrite() {
        store.attempt = attempt();
        store.account = account("DISABLED", 2, List.of("DENTIST"));
        var result = service.disable(actor, staff, 1, "Employment ended", key, correlation);
        assertEquals(2, result.version());
        assertEquals(0, store.disables);
        assertEquals(0, store.audits);
        assertEquals(List.of(), store.revoked);
    }

    @Test
    void rechecksAttemptAfterTargetLockForConcurrentReplay() {
        store.attemptAfterLock = attempt();
        store.account = account("DISABLED", 2, List.of("DENTIST"));
        var result = service.disable(actor, staff, 1, "Employment ended", key, correlation);
        assertEquals(2, result.version());
        assertEquals(0, store.disables);
    }

    @Test
    void rejectsKeyReuseAndIneligibleStaff() {
        store.attempt = new DisableStaffUnitOfWork.Attempt(actor, staff, "Another reason", 1, 2);
        assertThrows(ConcurrentModificationException.class,
            () -> service.disable(actor, staff, 1, "Employment ended", key, correlation));
        store.attempt = null;
        store.account = account("DISABLED", 1, List.of("DENTIST"));
        assertThrows(ConcurrentModificationException.class,
            () -> service.disable(actor, staff, 1, "Employment ended", key, correlation));
        store.account = account("ACTIVE", 2, List.of("DENTIST"));
        assertThrows(ConcurrentModificationException.class,
            () -> service.disable(actor, staff, 1, "Employment ended", key, correlation));
        store.account = account("ACTIVE", 1, List.of("ADMINISTRATOR"));
        assertThrows(SecurityException.class,
            () -> service.disable(actor, staff, 1, "Employment ended", key, correlation));
        assertEquals(0, store.disables);
    }

    @Test
    void rejectsUnauthorizedMissingAndMalformedRequests() {
        store.admin = false;
        assertThrows(SecurityException.class,
            () -> service.disable(actor, staff, 1, "Employment ended", key, correlation));
        store.admin = true;
        store.account = null;
        assertThrows(NoSuchElementException.class,
            () -> service.disable(actor, staff, 1, "Employment ended", key, correlation));
        for (String reason : List.of("", " ", " Leading", "Trailing ", "x".repeat(1001))) {
            assertThrows(IllegalArgumentException.class,
                () -> service.disable(actor, staff, 1, reason, key, correlation));
        }
        assertThrows(IllegalArgumentException.class,
            () -> service.disable(actor, staff, 0, "Employment ended", key, correlation));
        assertEquals(0, store.disables);
    }

    @Test
    void legacyMissingNameAndStaleReplayDoNotMutateAccount() {
        store.account = new DisableStaffUnitOfWork.Account(staff, "ada@example.test", null,
            "ACTIVE", 1, List.of("DENTIST"), NOW.minusSeconds(3600), NOW);
        assertThrows(ConcurrentModificationException.class,
            () -> service.disable(actor, staff, 1, "Employment ended", key, correlation));
        store.account = account("ACTIVE", 3, List.of("DENTIST"));
        store.attempt = attempt();
        assertThrows(ConcurrentModificationException.class,
            () -> service.disable(actor, staff, 1, "Employment ended", key, correlation));
        assertEquals(0, store.disables);
    }

    @Test
    void outboxFailurePreventsTransactionCommit() {
        store.failEvent = true;
        assertThrows(IllegalStateException.class,
            () -> service.disable(actor, staff, 1, "Employment ended", key, correlation));
        assertEquals(0, store.commits);
    }

    private DisableStaffUnitOfWork.Attempt attempt() {
        return new DisableStaffUnitOfWork.Attempt(actor, staff, "Employment ended", 1, 2);
    }

    private DisableStaffUnitOfWork.Account account(String status, long version,
                                                   List<String> roles) {
        return new DisableStaffUnitOfWork.Account(staff, "ada@example.test", "Ada Staff",
            status, version, roles, NOW.minusSeconds(3600), NOW);
    }

    private final class FakeStore implements DisableStaffUnitOfWork, DisableStaffUnitOfWork.Store {
        Account account = account("ACTIVE", 1, List.of("DENTIST"));
        Attempt attempt;
        Attempt attemptAfterLock;
        boolean lockedTarget;
        boolean admin = true;
        boolean failEvent;
        int disables;
        int audits;
        int commits;
        UUID auditCorrelation;
        Instant auditTime;
        List<UUID> revoked = new java.util.ArrayList<>();

        @Override public <T> T execute(Function<Store, T> operation) {
            var result = operation.apply(this);
            commits++;
            return result;
        }
        @Override public boolean activeAdministratorForUpdate(UUID actorId) { return admin; }
        @Override public Attempt findAttempt(UUID idempotencyKey) {
            return lockedTarget && attemptAfterLock != null ? attemptAfterLock : attempt;
        }
        @Override public Account findForUpdate(UUID userId) {
            lockedTarget = true;
            return account;
        }
        @Override public List<UUID> activeSessionsForUpdate(UUID userId) {
            return List.of(session);
        }
        @Override public void disable(UUID userId, long expectedVersion, Instant at) {
            disables++;
        }
        @Override public void appendAudit(UUID userId, UUID actorId, String priorStatus,
                                          String reason, long expectedVersion,
                                          UUID idempotencyKey, UUID correlationId, Instant at) {
            audits++;
            auditCorrelation = correlationId;
            auditTime = at;
        }
        @Override public void appendSessionRevoked(UUID sessionId, UUID userId, UUID actorId,
                                                   UUID correlationId, Instant at) {
            if (failEvent) throw new IllegalStateException("Outbox unavailable");
            revoked.add(sessionId);
        }
    }
}
