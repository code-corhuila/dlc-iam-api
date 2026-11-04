package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.EnableStaffUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class EnableStaffAccountServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-04T12:00:00Z");
    private final UUID actor = UUID.randomUUID();
    private final UUID staff = UUID.randomUUID();
    private final UUID key = UUID.randomUUID();
    private final UUID correlation = UUID.randomUUID();
    private final FakeStore store = new FakeStore();
    private final EnableStaffAccountService service = new EnableStaffAccountService(
        store, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void verifiedStaffReturnsActiveWithAudit() {
        var result = service.enable(actor, staff, 1, "Employment resumed", key, correlation);
        assertEquals("ACTIVE", result.status());
        assertEquals(2, result.version());
        assertEquals("ACTIVE", store.writtenStatus);
        assertEquals("ACTIVE", store.auditedStatus);
        assertEquals(correlation, store.auditCorrelation);
        assertEquals(NOW, store.auditTime);
        assertEquals(1, store.commits);
    }

    @Test
    void unverifiedStaffRemainsPendingVerification() {
        store.account = account(false, 1, "DISABLED", List.of("DENTIST"));
        var result = service.enable(actor, staff, 1, "Employment resumed", key, correlation);
        assertEquals("PENDING_VERIFICATION", result.status());
        assertEquals("PENDING_VERIFICATION", store.writtenStatus);
        assertEquals(1, store.audits);
    }

    @Test
    void exactRetryAndConcurrentReplayDoNotWriteAgain() {
        store.attempt = attempt();
        assertEquals(2, service.enable(actor, staff, 1, "Employment resumed", key,
            correlation).version());
        assertEquals(0, store.writes);
        store.attempt = null;
        store.attemptAfterLock = attempt();
        assertEquals(2, service.enable(actor, staff, 1, "Employment resumed", key,
            correlation).version());
        assertEquals(0, store.writes);
    }

    @Test
    void rejectsKeyReuseAndInvalidStates() {
        store.attempt = new EnableStaffUnitOfWork.Attempt(actor, staff, "Different reason",
            1, "ACTIVE", 2);
        assertThrows(ConcurrentModificationException.class,
            () -> service.enable(actor, staff, 1, "Employment resumed", key, correlation));
        store.attempt = null;
        store.account = account(true, 1, "ACTIVE", List.of("DENTIST"));
        assertThrows(ConcurrentModificationException.class,
            () -> service.enable(actor, staff, 1, "Employment resumed", key, correlation));
        store.account = account(true, 2, "DISABLED", List.of("DENTIST"));
        assertThrows(ConcurrentModificationException.class,
            () -> service.enable(actor, staff, 1, "Employment resumed", key, correlation));
        store.account = account(true, 1, "DISABLED", List.of("ADMINISTRATOR"));
        assertThrows(SecurityException.class,
            () -> service.enable(actor, staff, 1, "Employment resumed", key, correlation));
        assertEquals(0, store.writes);
    }

    @Test
    void rejectsUnauthorizedMissingAndMalformedRequests() {
        store.admin = false;
        assertThrows(SecurityException.class,
            () -> service.enable(actor, staff, 1, "Employment resumed", key, correlation));
        store.admin = true;
        store.account = null;
        assertThrows(NoSuchElementException.class,
            () -> service.enable(actor, staff, 1, "Employment resumed", key, correlation));
        for (String reason : List.of("", " ", " Leading", "Trailing ", "x".repeat(1001))) {
            assertThrows(IllegalArgumentException.class,
                () -> service.enable(actor, staff, 1, reason, key, correlation));
        }
        assertThrows(IllegalArgumentException.class,
            () -> service.enable(actor, staff, 0, "Employment resumed", key, correlation));
        assertEquals(0, store.writes);
    }

    @Test
    void auditFailurePreventsTransactionCommit() {
        store.failAudit = true;
        assertThrows(IllegalStateException.class,
            () -> service.enable(actor, staff, 1, "Employment resumed", key, correlation));
        assertEquals(0, store.commits);
    }

    private EnableStaffUnitOfWork.Account account(boolean verified, long version,
                                                  String status, List<String> roles) {
        return new EnableStaffUnitOfWork.Account(staff, status, verified, version, roles);
    }

    private EnableStaffUnitOfWork.Attempt attempt() {
        return new EnableStaffUnitOfWork.Attempt(actor, staff, "Employment resumed", 1,
            "ACTIVE", 2);
    }

    private final class FakeStore implements EnableStaffUnitOfWork, EnableStaffUnitOfWork.Store {
        Account account = account(true, 1, "DISABLED", List.of("SECRETARY_ASSISTANT"));
        Attempt attempt;
        Attempt attemptAfterLock;
        boolean lockedTarget;
        boolean admin = true;
        boolean failAudit;
        int writes;
        int audits;
        int commits;
        String writtenStatus;
        String auditedStatus;
        UUID auditCorrelation;
        Instant auditTime;

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
        @Override public void enable(UUID userId, long expectedVersion,
                                     String nextStatus, Instant at) {
            writes++;
            writtenStatus = nextStatus;
        }
        @Override public void appendAudit(UUID userId, UUID actorId, String nextStatus,
                                          String reason, long expectedVersion,
                                          UUID idempotencyKey, UUID correlationId, Instant at) {
            if (failAudit) throw new IllegalStateException("Audit unavailable");
            audits++;
            auditedStatus = nextStatus;
            auditCorrelation = correlationId;
            auditTime = at;
        }
    }
}
