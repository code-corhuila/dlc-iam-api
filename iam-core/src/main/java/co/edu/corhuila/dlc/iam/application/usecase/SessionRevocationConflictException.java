package co.edu.corhuila.dlc.iam.application.usecase;

public final class SessionRevocationConflictException extends IllegalStateException {
    private final String code;

    public SessionRevocationConflictException(String code, String message) {
        super(message);
        this.code = code;
    }

    public SessionRevocationConflictException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() { return code; }
}
