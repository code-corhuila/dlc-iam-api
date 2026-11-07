package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.in.VerifyStaffEmail;
import co.edu.corhuila.dlc.iam.application.port.out.ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.port.out.EmailVerificationUnitOfWork;
import java.time.Clock;
import java.util.UUID;

public final class VerifyStaffEmailService implements VerifyStaffEmail {
    private static final String PURPOSE = "EMAIL_VERIFICATION";
    private final EmailVerificationUnitOfWork unitOfWork;
    private final ChallengeTokenHasher hasher;
    private final Clock clock;

    public VerifyStaffEmailService(EmailVerificationUnitOfWork unitOfWork,
                                   ChallengeTokenHasher hasher, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.hasher = hasher;
        this.clock = clock;
    }

    @Override
    public void verify(String token, UUID correlationId) {
        if (token == null || token.isBlank() || token.length() > 512
            || correlationId == null) {
            throw new IllegalArgumentException("Invalid verification request");
        }
        String tokenHash = hasher.hash(token);
        var now = clock.instant();
        unitOfWork.execute(store -> {
            var challenge = store.findForUpdate(tokenHash, PURPOSE);
            if (challenge == null || !PURPOSE.equals(challenge.purpose())
                || challenge.consumedAt() != null || challenge.expiresAt() == null
                || !now.isBefore(challenge.expiresAt())) {
                throw new InvalidVerificationChallengeException();
            }
            if (!store.consume(challenge.id(), now)
                || !store.activatePendingUser(challenge.userId(), now)) {
                throw new InvalidVerificationChallengeException();
            }
            store.appendUserEmailVerified(UUID.randomUUID(), challenge.userId(),
                correlationId, now);
            return null;
        });
    }
}
