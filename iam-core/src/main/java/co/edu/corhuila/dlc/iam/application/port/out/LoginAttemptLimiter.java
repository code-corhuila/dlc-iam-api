package co.edu.corhuila.dlc.iam.application.port.out;

public interface LoginAttemptLimiter {
    boolean record(String peerIp);
}
