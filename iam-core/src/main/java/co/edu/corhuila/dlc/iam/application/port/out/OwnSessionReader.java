package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface OwnSessionReader {
    Page read(UUID ownerId, int limit, long offset);

    record Page(long total, List<Session> sessions) { }

    record Session(UUID id, String device, Instant createdAt,
                   Instant lastUserActivityAt, Instant expiresAt, long version) { }
}
