package co.edu.corhuila.dlc.iam.application.port.out;

/** A keyed, non-reversible proof of a registration request for durable replay comparison. */
public interface RegistrationRequestProof {
    byte[] prove(String normalizedEmail, String password, String name, String role);
}
