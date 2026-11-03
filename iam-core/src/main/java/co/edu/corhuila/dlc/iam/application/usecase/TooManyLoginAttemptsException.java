package co.edu.corhuila.dlc.iam.application.usecase;

public final class TooManyLoginAttemptsException extends RuntimeException {
    public TooManyLoginAttemptsException() {
        super("Too many login attempts");
    }
}
