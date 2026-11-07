package co.edu.corhuila.dlc.iam.application.port.out;

public interface RefreshCredential {
    String generate();
    String hash(String raw);
}
