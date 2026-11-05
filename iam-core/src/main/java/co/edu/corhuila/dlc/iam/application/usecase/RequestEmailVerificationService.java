package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.port.out.RecoveryTokenGenerator;
import co.edu.corhuila.dlc.iam.application.port.out.VerificationEmailSender;
import co.edu.corhuila.dlc.iam.application.port.out.VerificationRequestLimiter;
import co.edu.corhuila.dlc.iam.application.port.out.VerificationRequestUnitOfWork;
import java.time.Clock;
import java.time.Duration;
import java.util.Locale;
import java.util.UUID;

public final class RequestEmailVerificationService {
    private static final System.Logger LOG = System.getLogger(RequestEmailVerificationService.class.getName());
    private final VerificationRequestUnitOfWork unitOfWork;
    private final VerificationRequestLimiter limiter;
    private final RecoveryTokenGenerator tokens;
    private final ChallengeTokenHasher hasher;
    private final VerificationEmailSender emailSender;
    private final Clock clock;

    public RequestEmailVerificationService(VerificationRequestUnitOfWork unitOfWork,
            VerificationRequestLimiter limiter, RecoveryTokenGenerator tokens,
            ChallengeTokenHasher hasher, VerificationEmailSender emailSender, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.limiter = limiter;
        this.tokens = tokens;
        this.hasher = hasher;
        this.emailSender = emailSender;
        this.clock = clock;
    }

    public void request(String email, String requesterKey, UUID correlationId) {
        if (email == null || requesterKey == null || requesterKey.isBlank()
            || correlationId == null) {
            throw new IllegalArgumentException("Invalid verification request");
        }
        String normalized = email.strip().toLowerCase(Locale.ROOT);
        if (normalized.length() > 255
            || !normalized.matches("[^@\\s]+@[^@\\s]+\\.[^@\\s]+")) {
            throw new IllegalArgumentException("Invalid verification request");
        }
        if (!limiter.allowVerification(requesterKey, normalized)) {
            throw new RecoveryRateLimitedException();
        }
        String token = unitOfWork.execute(store -> {
            UUID userId = store.pendingUserForUpdate(normalized);
            if (userId == null) return null;
            String raw = tokens.generate();
            if (raw == null || raw.isBlank() || raw.length() > 512) {
                throw new IllegalStateException("Verification token generator failed");
            }
            var now = clock.instant();
            store.replaceChallenge(UUID.randomUUID(), userId, hasher.hash(raw),
                now, now.plus(Duration.ofHours(24)));
            return raw;
        });
        if (token != null) {
            try {
                emailSender.sendEmailVerification(normalized, token, correlationId);
            } catch (RuntimeException providerFailure) {
                LOG.log(System.Logger.Level.WARNING,
                    "IAM verification delivery failed; correlationId=" + correlationId);
            }
        }
    }
}
