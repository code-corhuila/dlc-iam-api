package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface SessionSnapshotReader {
    Snapshot find(UUID userId, UUID sessionId);

    record Snapshot(String status, Instant verifiedAt, Instant lockedUntil,
                    Instant revokedAt, Instant inactivityExpiresAt, List<String> roles) { }
}
