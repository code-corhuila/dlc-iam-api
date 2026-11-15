package co.edu.corhuila.dlc.iam.application.port.out;

/** Applies the verification issuance limit even when no account exists. */
public interface VerificationRequestLimiter {
    boolean allowVerification(String requesterKey, String normalizedEmail);
}
