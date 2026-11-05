package co.edu.corhuila.dlc.iam.application.port.out;

/** Produces an opaque, unpredictable credential with at least 256 bits of entropy. */
public interface RecoveryTokenGenerator {
    String generate();
}
