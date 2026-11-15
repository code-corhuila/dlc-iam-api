package co.edu.corhuila.dlc.iam.application.port.out;

public interface PasswordHasher {
    String hash(String rawPassword);
}
