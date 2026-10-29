package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.SessionSnapshotReader;
import java.time.Clock;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public final class ValidateSessionService {
    private final SessionSnapshotReader reader;
    private final Clock clock;

    public ValidateSessionService(SessionSnapshotReader reader, Clock clock) {
        this.reader = reader;
        this.clock = clock;
    }

    public boolean active(UUID userId, UUID sessionId, List<String> tokenRoles) {
        var state = reader.find(userId, sessionId);
        return state != null && "ACTIVE".equals(state.status())
            && state.verifiedAt() != null && state.lockedUntil() == null
            && state.revokedAt() == null && state.inactivityExpiresAt() != null
            && state.inactivityExpiresAt().isAfter(clock.instant())
            && tokenRoles != null && !tokenRoles.isEmpty()
            && tokenRoles.size() == Set.copyOf(tokenRoles).size()
            && Set.copyOf(tokenRoles).equals(Set.copyOf(state.roles()));
    }
}
