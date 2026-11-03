package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;

public interface LoginIpAttemptWindow {
    /** Atomically serialize one digest, count its window and insert only if below the limit. */
    boolean recordIfBelowLimit(byte[] ipDigest, Instant after, Instant at, int limit);
}
