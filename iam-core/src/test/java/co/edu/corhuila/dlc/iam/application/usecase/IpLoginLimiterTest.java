package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.LoginIpAttemptWindow;
import java.net.InetAddress;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class IpLoginLimiterTest {
    private static final Instant NOW = Instant.parse("2026-11-02T10:00:00Z");

    @Test
    void recordsTenAttemptsThenRejectsWithHmacDigestAndFiveMinuteWindow() throws Exception {
        var window = new FakeWindow();
        var limiter = new IpLoginLimiter(window, new byte[32], Clock.fixed(NOW, ZoneOffset.UTC));
        var ip = InetAddress.getByName("192.0.2.10");
        for (int attempt = 0; attempt < 10; attempt++) limiter.checkAndRecord(ip);
        assertThrows(TooManyLoginAttemptsException.class, () -> limiter.checkAndRecord(ip));
        assertEquals(11, window.calls);
        assertEquals(10, window.limit);
        assertEquals(NOW.minusSeconds(300), window.after);
        assertEquals(NOW, window.at);
        assertEquals(32, window.digest.length);
        assertFalse(Arrays.equals(ip.getAddress(), window.digest));
    }

    @Test
    void refusesMissingSourceAndShortDigestKey() {
        var window = new FakeWindow();
        assertThrows(IllegalArgumentException.class,
            () -> new IpLoginLimiter(window, new byte[16], Clock.systemUTC()));
        var limiter = new IpLoginLimiter(window, new byte[32], Clock.systemUTC());
        assertThrows(IllegalArgumentException.class, () -> limiter.checkAndRecord(null));
        assertEquals(0, window.calls);
    }

    private static final class FakeWindow implements LoginIpAttemptWindow {
        byte[] digest;
        Instant after;
        Instant at;
        int limit;
        int calls;

        public boolean recordIfBelowLimit(byte[] digest, Instant after, Instant at, int limit) {
            this.digest = digest;
            this.after = after;
            this.at = at;
            this.limit = limit;
            return ++calls <= limit;
        }
    }
}
