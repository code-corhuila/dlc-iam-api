package co.edu.corhuila.dlc.iam.application.usecase;

public final class InvalidRecoveryChallengeException extends RuntimeException {
    public InvalidRecoveryChallengeException() {
        super("Invalid or expired recovery token");
    }
}
