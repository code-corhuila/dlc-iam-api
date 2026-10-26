package co.edu.corhuila.dlc.iam.application.port.out;

public interface ChallengeTokenHasher {
    String hash(String rawToken);
}
