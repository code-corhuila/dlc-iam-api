package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.in.ReplaceRoleAssignments;
import co.edu.corhuila.dlc.iam.application.port.out.RoleAssignmentUnitOfWork;
import java.time.Clock;
import java.util.ConcurrentModificationException;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

public final class ReplaceRoleAssignmentsService implements ReplaceRoleAssignments {
    private static final Set<String> ASSIGNABLE = Set.of("DENTIST", "SECRETARY_ASSISTANT");
    private final RoleAssignmentUnitOfWork unitOfWork;
    private final Clock clock;

    public ReplaceRoleAssignmentsService(RoleAssignmentUnitOfWork unitOfWork, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.clock = clock;
    }

    @Override
    public Staff replace(UUID actorId, UUID userId, List<String> roles,
                         long expectedVersion, String reason, UUID correlationId) {
        if (actorId == null || userId == null || correlationId == null || roles == null
            || roles.isEmpty() || roles.stream().anyMatch(role -> role == null || !ASSIGNABLE.contains(role))
            || new HashSet<>(roles).size() != roles.size() || expectedVersion < 0
            || reason == null || reason.isBlank() || reason.length() > 1000) {
            throw new IllegalArgumentException("Invalid role assignment request");
        }
        List<String> requested = List.copyOf(roles);
        return unitOfWork.execute(store -> {
            if (!store.activeAdministratorForUpdate(actorId)) {
                throw new SecurityException("Administrator required");
            }
            var target = store.findForUpdate(userId);
            if (target == null) {
                throw new NoSuchElementException("Staff user not found");
            }
            if (target.version() != expectedVersion) {
                throw new ConcurrentModificationException("Staff version changed");
            }
            if (target.roles().contains("ADMINISTRATOR")) {
                throw new SecurityException("Bootstrap Administrator cannot be changed");
            }
            Set<String> previous = Set.copyOf(target.roles());
            Set<String> next = Set.copyOf(requested);
            if (previous.equals(next)) {
                return view(target, target.version(), target.roles());
            }
            var at = clock.instant();
            store.replaceRoles(userId, requested, expectedVersion);
            for (String role : previous) {
                if (!next.contains(role)) {
                    store.appendAudit(userId, role, "REVOKED", actorId, reason, correlationId, at);
                    store.appendRoleEvent("RoleRevokedFromUser", userId, role, actorId,
                        correlationId, at);
                }
            }
            for (String role : requested) {
                if (!previous.contains(role)) {
                    store.appendAudit(userId, role, "ASSIGNED", actorId, reason, correlationId, at);
                    store.appendRoleEvent("RoleAssignedToUser", userId, role, actorId,
                        correlationId, at);
                }
            }
            store.revokeSessions(userId, actorId, correlationId, at);
            return view(target, expectedVersion + 1, requested);
        });
    }

    private static Staff view(RoleAssignmentUnitOfWork.StaffAccount account,
                              long version, List<String> roles) {
        return new Staff(account.id(), account.email(), account.name(),
            List.copyOf(roles), account.status(), version);
    }
}
