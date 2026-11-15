package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.LogoutUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import java.time.Clock;
import java.util.List;
import java.util.UUID;

public final class LogoutService {
    private final LogoutUnitOfWork unitOfWork;
    private final RefreshCredential credentials;
    private final Clock clock;

    public LogoutService(LogoutUnitOfWork unitOfWork, RefreshCredential credentials, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.credentials = credentials;
        this.clock = clock;
    }

    /** The cookie identifies the user; no access JWT or client-selected user is accepted. */
    public void logout(String rawRefresh, boolean allDevices, UUID correlationId) {
        if (rawRefresh == null || rawRefresh.isBlank() || rawRefresh.length() > 512
            || correlationId == null) throw new IllegalArgumentException("Invalid logout request");
        var now = clock.instant();
        String tokenHash = credentials.hash(rawRefresh);
        boolean authenticated = unitOfWork.execute(store -> {
            var credential = store.findForUpdate(tokenHash);
            if (credential == null || credential.consumedAt() != null
                || credential.revokedAt() != null || credential.familyRevokedAt() != null
                || credential.sessionRevokedAt() != null
                || !credential.expiresAt().isAfter(now)
                || !credential.inactivityExpiresAt().isAfter(now)) return false;
            List<UUID> sessions = List.copyOf(store.activeSessionsForUpdate(
                credential.userId(), credential.sessionId(), allDevices));
            if (!sessions.contains(credential.sessionId())) return false;
            for (UUID sessionId : sessions) {
                if (!store.revokeSession(credential.userId(), sessionId, now)) {
                    throw new IllegalStateException("Session changed during logout");
                }
                store.appendSessionRevoked(UUID.randomUUID(), credential.userId(), sessionId,
                    correlationId, now);
            }
            return true;
        });
        if (!authenticated) throw new InvalidLoginException();
    }
}
