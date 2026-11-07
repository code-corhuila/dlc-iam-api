package co.edu.corhuila.dlc.iam.application.usecase;

public final class InvalidLoginException extends RuntimeException {
    public InvalidLoginException() {
        super("Authentication could not be completed.");
    }
}
