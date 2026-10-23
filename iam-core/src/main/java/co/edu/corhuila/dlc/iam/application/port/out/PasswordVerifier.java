package co.edu.corhuila.dlc.iam.application.port.out;

public interface PasswordVerifier {
    boolean matches(String raw, String encoded);
    void dummyCheck(String raw);
}
