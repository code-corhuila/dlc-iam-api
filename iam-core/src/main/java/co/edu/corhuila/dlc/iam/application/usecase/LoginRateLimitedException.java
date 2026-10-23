package co.edu.corhuila.dlc.iam.application.usecase;

public final class LoginRateLimitedException extends RuntimeException {
    public LoginRateLimitedException() {
        super("Too many login attempts");
    }
}
