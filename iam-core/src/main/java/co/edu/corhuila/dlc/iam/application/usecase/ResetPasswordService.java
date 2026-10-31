package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.in.ResetPassword;
import co.edu.corhuila.dlc.iam.application.port.out.ChallengeTokenHasher;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordHasher;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordResetUnitOfWork;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.UUID;

public final class ResetPasswordService implements ResetPassword {
    private static final String PURPOSE = "PASSWORD_RECOVERY";
    private final PasswordResetUnitOfWork unitOfWork;
    private final ChallengeTokenHasher tokens;
    private final PasswordHasher passwords;
    private final Clock clock;

    public ResetPasswordService(PasswordResetUnitOfWork unitOfWork,
                                ChallengeTokenHasher tokens, PasswordHasher passwords,
                                Clock clock) {
        this.unitOfWork = unitOfWork;
        this.tokens = tokens;
        this.passwords = passwords;
        this.clock = clock;
    }

    @Override
    public void reset(String token, String newPassword, UUID correlationId) {
        if (token == null || token.isBlank() || token.length() > 512
            || newPassword == null || newPassword.length() < 8
            || newPassword.getBytes(StandardCharsets.UTF_8).length > 72
            || !newPassword.matches("(?s).*[A-Z].*")
            || !newPassword.matches("(?s).*[0-9].*") || correlationId == null) {
            throw new IllegalArgumentException("Invalid password reset request");
        }
        String tokenHash = tokens.hash(token);
        String passwordHash = passwords.hash(newPassword);
        var now = clock.instant();
        unitOfWork.execute(store -> {
            var challenge = store.findForUpdate(tokenHash, PURPOSE);
            if (challenge == null || !PURPOSE.equals(challenge.purpose())
                || challenge.consumedAt() != null || challenge.expiresAt() == null
                || !now.isBefore(challenge.expiresAt())
                || !store.consume(challenge.id(), now)
                || !store.changePassword(challenge.userId(), passwordHash, now)) {
                throw new InvalidRecoveryChallengeException();
            }
            store.revokeSessions(challenge.userId(), correlationId, now);
            return null;
        });
    }
}
