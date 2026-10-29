package co.edu.corhuila.dlc.iam.application.port.in;

import java.util.List;
import java.util.UUID;

public interface ReplaceRoleAssignments {
    Staff replace(UUID actorId, UUID userId, List<String> roles,
                  long expectedVersion, String reason, UUID correlationId);

    record Staff(UUID id, String email, String name, List<String> roles,
                 String status, long version) { }
}
