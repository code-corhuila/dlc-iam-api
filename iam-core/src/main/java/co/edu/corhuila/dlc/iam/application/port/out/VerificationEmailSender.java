package co.edu.corhuila.dlc.iam.application.port.out;

import java.util.UUID;

/** IAM verification email delivery without storing or logging the raw credential. */
public interface VerificationEmailSender {
    void sendEmailVerification(String normalizedEmail, String rawToken, UUID correlationId);
}
