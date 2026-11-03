package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.LoginIpAttemptWindow;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class IpLoginLimiter {
    private static final int LIMIT = 10;
    private static final Duration WINDOW = Duration.ofMinutes(5);
    private final LoginIpAttemptWindow attempts;
    private final byte[] digestKey;
    private final Clock clock;

    public IpLoginLimiter(LoginIpAttemptWindow attempts, byte[] digestKey, Clock clock) {
        if (attempts == null || digestKey == null || digestKey.length < 32 || clock == null) {
            throw new IllegalArgumentException("A 256-bit IP digest key is required");
        }
        this.attempts = attempts;
        this.digestKey = digestKey.clone();
        this.clock = clock;
    }

    /** Source must come from a trusted connection/proxy policy, never a client-supplied header. */
    public void checkAndRecord(InetAddress source) {
        if (source == null) throw new IllegalArgumentException("Source address required");
        var at = clock.instant();
        if (!attempts.recordIfBelowLimit(digest(source), at.minus(WINDOW), at, LIMIT)) {
            throw new TooManyLoginAttemptsException();
        }
    }

    private byte[] digest(InetAddress source) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(digestKey, "HmacSHA256"));
            return mac.doFinal(source.getAddress());
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("Cannot digest source address", failure);
        }
    }
}
