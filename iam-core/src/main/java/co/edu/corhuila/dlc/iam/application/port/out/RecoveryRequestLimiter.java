package co.edu.corhuila.dlc.iam.application.port.out;

/** Applies the same request policy whether or not the email belongs to an account. */
public interface RecoveryRequestLimiter {
    boolean allow(String requesterKey, String normalizedEmail);
}
