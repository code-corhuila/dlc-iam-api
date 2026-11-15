package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.OwnSessionReader;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class ListOwnSessionsService {
    private final OwnSessionReader reader;

    public ListOwnSessionsService(OwnSessionReader reader) {
        this.reader = reader;
    }

    public Page list(UUID ownerId, UUID currentSessionId, int page, int limit) {
        if (ownerId == null || currentSessionId == null || page < 1 || limit < 1 || limit > 100) {
            throw new IllegalArgumentException("Invalid session page");
        }
        long offset = ((long) page - 1) * limit;
        var result = reader.read(ownerId, limit, offset);
        List<Session> sessions = result.sessions().stream()
            .map(row -> new Session(row.id(), row.device(), row.expiresAt(),
                row.id().equals(currentSessionId), row.createdAt(), row.version(),
                row.lastUserActivityAt()))
            .toList();
        long totalPages = result.total() / limit + (result.total() % limit == 0 ? 0 : 1);
        return new Page(sessions, new Meta(page, limit, result.total(), totalPages));
    }

    public record Page(List<Session> data, Meta meta) { }
    public record Meta(int page, int limit, long total, long totalPages) { }
    public record Session(UUID id, String device, Instant expiresAt, boolean current,
                          Instant createdAt, long version, Instant lastUserActivityAt) { }
}
