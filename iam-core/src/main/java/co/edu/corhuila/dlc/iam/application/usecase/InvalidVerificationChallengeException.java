package co.edu.corhuila.dlc.iam.application.usecase;

public final class InvalidVerificationChallengeException extends RuntimeException {
    public InvalidVerificationChallengeException() {
        super("Invalid or expired verification token");
    }
}
