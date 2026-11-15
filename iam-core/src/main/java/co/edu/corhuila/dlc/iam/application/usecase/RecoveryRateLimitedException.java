package co.edu.corhuila.dlc.iam.application.usecase;

public final class RecoveryRateLimitedException extends RuntimeException {
    public RecoveryRateLimitedException() {
        super("Recovery request limit exceeded");
    }
}
