package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.port.out.RecoveryRequestLimiter;
import co.edu.corhuila.dlc.iam.application.port.out.RecoveryRequestUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RecoveryTokenGenerator;
import java.time.Clock;
import java.time.Duration;
import java.util.Locale;
import java.util.UUID;

public final class RequestPasswordRecoveryService {
    private static final String PURPOSE = "PASSWORD_RECOVERY";
    private final RecoveryRequestUnitOfWork unitOfWork;
    private final RecoveryRequestLimiter limiter;
    private final RecoveryTokenGenerator tokens;
    private final ChallengeTokenHasher hasher;
    private final Clock clock;
    private final Duration ttl;

    public RequestPasswordRecoveryService(RecoveryRequestUnitOfWork unitOfWork,
            RecoveryRequestLimiter limiter, RecoveryTokenGenerator tokens,
            ChallengeTokenHasher hasher, Clock clock, Duration ttl) {
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("Recovery expiry must be positive");
        }
        this.unitOfWork = unitOfWork;
        this.limiter = limiter;
        this.tokens = tokens;
        this.hasher = hasher;
        this.clock = clock;
        this.ttl = ttl;
    }

    /** A successful call has the same result for known and unknown addresses. */
    public void request(String email, String requesterKey, UUID correlationId) {
        if (email == null || requesterKey == null || requesterKey.isBlank()
            || correlationId == null) {
            throw new IllegalArgumentException("Invalid recovery request");
        }
        String normalized = email.strip().toLowerCase(Locale.ROOT);
        if (normalized.length() > 255
            || !normalized.matches("[^@\\s]+@[^@\\s]+\\.[^@\\s]+")) {
            throw new IllegalArgumentException("Invalid recovery request");
        }
        if (!limiter.allow(requesterKey, normalized)) {
            throw new RecoveryRateLimitedException();
        }
        unitOfWork.execute(store -> {
            UUID userId = store.verifiedUserForUpdate(normalized);
            if (userId != null) {
                String rawToken = tokens.generate();
                if (rawToken == null || rawToken.isBlank() || rawToken.length() > 512) {
                    throw new IllegalStateException("Recovery token generator failed");
                }
                var now = clock.instant();
                store.createChallenge(UUID.randomUUID(), userId, PURPOSE, hasher.hash(rawToken),
                    now, now.plus(ttl));
                store.queueDelivery(userId, normalized, rawToken, correlationId);
            }
            return null;
        });
    }
}
