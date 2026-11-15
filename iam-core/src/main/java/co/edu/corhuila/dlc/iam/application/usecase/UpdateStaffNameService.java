package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.StaffNameUnitOfWork;
import java.time.Clock;
import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;
import java.util.UUID;

public final class UpdateStaffNameService {
    private final StaffNameUnitOfWork unitOfWork;
    private final Clock clock;

    public UpdateStaffNameService(StaffNameUnitOfWork unitOfWork, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.clock = clock;
    }

    public Result update(UUID actorId, UUID userId, String name,
                         long expectedVersion, UUID correlationId) {
        if (actorId == null || userId == null || correlationId == null || name == null
            || name.isBlank() || !name.equals(name.strip()) || name.length() > 100
            || expectedVersion < 1) {
            throw new IllegalArgumentException("Invalid staff name update");
        }
        return unitOfWork.execute(store -> {
            if (!store.activeAdministrator(actorId)) {
                throw new SecurityException("Administrator required");
            }
            var staff = store.findForUpdate(userId);
            if (staff == null) {
                throw new NoSuchElementException("Staff not found");
            }
            if (staff.version() != expectedVersion) {
                throw new ConcurrentModificationException("Staff version changed");
            }
            if (name.equals(staff.name())) {
                return view(staff, name, staff.updatedAt(), staff.version());
            }
            var now = clock.instant();
            store.updateName(userId, name, expectedVersion, now);
            store.appendAudit(userId, actorId, staff.status(), correlationId, now);
            return view(staff, name, now, expectedVersion + 1);
        });
    }

    private static Result view(StaffNameUnitOfWork.Staff staff, String name,
                               java.time.Instant updatedAt, long version) {
        return new Result(staff.id(), staff.email(), name, staff.roles(), staff.status(),
            staff.createdAt(), updatedAt, version);
    }

    public record Result(UUID id, String email, String name, java.util.List<String> roles,
                         String status, java.time.Instant createdAt,
                         java.time.Instant updatedAt, long version) { }
}
