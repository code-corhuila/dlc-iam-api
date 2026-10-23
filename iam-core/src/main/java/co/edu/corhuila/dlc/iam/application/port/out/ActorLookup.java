package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface ActorLookup {
    List<String> activeRoles(UUID userId, UUID sessionId, Instant now);
}
