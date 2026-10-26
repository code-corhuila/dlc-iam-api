package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.RoleAssignmentUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class ReplaceRoleAssignmentsServiceTest {
    private static final UUID ACTOR = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID STAFF = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID CORRELATION = UUID.fromString("00000000-0000-0000-0000-000000000003");
    private static final Instant NOW = Instant.parse("2026-10-26T12:00:00Z");
    private final FakeStore store = new FakeStore();
    private final ReplaceRoleAssignmentsService service = new ReplaceRoleAssignmentsService(
        store, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void changesOnlyTheDifferenceAndRevokesStaleSessions() {
        var result = service.replace(ACTOR, STAFF, List.of("SECRETARY_ASSISTANT"),
            4, "Duty change", CORRELATION);

        assertEquals(List.of("SECRETARY_ASSISTANT"), result.roles());
        assertEquals(5, result.version());
        assertEquals(List.of("REVOKED:DENTIST", "ASSIGNED:SECRETARY_ASSISTANT"), store.audit);
        assertEquals(List.of("RoleRevokedFromUser:DENTIST",
            "RoleAssignedToUser:SECRETARY_ASSISTANT"), store.events);
        assertEquals(1, store.replacements);
        assertEquals(1, store.revocations);
        assertEquals("Duty change", store.reason);
        assertEquals(CORRELATION, store.correlation);
        assertEquals(NOW, store.occurredAt);
    }

    @Test
    void unchangedAssignmentsDoNotWriteOrRevoke() {
        var result = service.replace(ACTOR, STAFF, List.of("DENTIST"),
            4, "No change", CORRELATION);

        assertEquals(4, result.version());
        assertEquals(0, store.replacements);
        assertEquals(0, store.revocations);
        assertEquals(List.of(), store.events);
    }

    @Test
    void rejectsUnapprovedDuplicateEmptyAndInvalidRequestsBeforeStorage() {
        for (var roles : List.of(List.<String>of(), List.of("PATIENT"),
            List.of("ADMINISTRATOR"), List.of("DENTIST", "DENTIST"))) {
            assertThrows(IllegalArgumentException.class,
                () -> service.replace(ACTOR, STAFF, roles, 4, "Reason", CORRELATION));
        }
        assertThrows(IllegalArgumentException.class,
            () -> service.replace(ACTOR, STAFF, List.of("DENTIST"), 4, " ", CORRELATION));
        assertThrows(IllegalArgumentException.class,
            () -> service.replace(ACTOR, STAFF, List.of("DENTIST"), -1, "Reason", CORRELATION));
        assertEquals(0, store.executions);
    }

    @Test
    void rejectsNonAdministratorMissingStaffStaleVersionAndBootstrapAdministrator() {
        store.administrator = false;
        assertThrows(SecurityException.class,
            () -> service.replace(ACTOR, STAFF, List.of("SECRETARY_ASSISTANT"),
                4, "Reason", CORRELATION));
        store.administrator = true;
        store.account = null;
        assertThrows(NoSuchElementException.class,
            () -> service.replace(ACTOR, STAFF, List.of("SECRETARY_ASSISTANT"),
                4, "Reason", CORRELATION));
        store.account = account(List.of("DENTIST"));
        assertThrows(ConcurrentModificationException.class,
            () -> service.replace(ACTOR, STAFF, List.of("SECRETARY_ASSISTANT"),
                3, "Reason", CORRELATION));
        store.account = account(List.of("ADMINISTRATOR"));
        assertThrows(SecurityException.class,
            () -> service.replace(ACTOR, STAFF, List.of("DENTIST"),
                4, "Reason", CORRELATION));
        assertEquals(0, store.replacements);
    }

    @Test
    void eventWriteFailureFailsTheWholeUseCase() {
        store.failEvent = true;
        assertThrows(IllegalStateException.class,
            () -> service.replace(ACTOR, STAFF, List.of("SECRETARY_ASSISTANT"),
                4, "Reason", CORRELATION));
        assertEquals(1, store.executions);
        assertEquals(0, store.committedTransactions);
    }

    private static RoleAssignmentUnitOfWork.StaffAccount account(List<String> roles) {
        return new RoleAssignmentUnitOfWork.StaffAccount(STAFF, "staff@example.test",
            "Ada Staff", "ACTIVE", 4, roles);
    }

    private static final class FakeStore implements RoleAssignmentUnitOfWork,
                                                    RoleAssignmentUnitOfWork.Store {
        StaffAccount account = account(List.of("DENTIST"));
        boolean administrator = true;
        boolean failEvent;
        int executions;
        int committedTransactions;
        int replacements;
        int revocations;
        String reason;
        UUID correlation;
        Instant occurredAt;
        List<String> audit = new ArrayList<>();
        List<String> events = new ArrayList<>();

        public <T> T execute(Function<Store, T> operation) {
            executions++;
            T result = operation.apply(this);
            committedTransactions++;
            return result;
        }
        public boolean activeAdministratorForUpdate(UUID actorId) { return administrator; }
        public StaffAccount findForUpdate(UUID userId) { return account; }
        public void replaceRoles(UUID userId, List<String> roles, long expectedVersion) {
            replacements++;
        }
        public void appendAudit(UUID userId, String role, String action, UUID actorId,
                                String auditReason, UUID correlationId, Instant at) {
            audit.add(action + ":" + role);
            reason = auditReason;
            correlation = correlationId;
            occurredAt = at;
        }
        public void appendRoleEvent(String eventType, UUID userId, String role,
                                    UUID actorId, UUID correlationId, Instant at) {
            if (failEvent) throw new IllegalStateException("outbox failure");
            events.add(eventType + ":" + role);
        }
        public void revokeSessions(UUID userId, UUID actorId, UUID correlationId, Instant at) {
            revocations++;
        }
    }
}
