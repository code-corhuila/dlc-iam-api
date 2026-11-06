package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.adapter.in.http.TrustedGatewayClientAddress;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class TrustedGatewayClientAddressTest {
    @Test
    void ignoresSpoofedHeaderFromUntrustedPeer() {
        var resolver = new TrustedGatewayClientAddress("172.25.0.10");
        var request = request("172.25.0.11", "203.0.113.8");
        assertEquals("172.25.0.11", resolver.resolve(request).getHostAddress());
    }

    @Test
    void trustsNobodyWhenGatewayAddressIsUnset() {
        var resolver = new TrustedGatewayClientAddress("");
        assertEquals("172.25.0.10", resolver.resolve(
            request("172.25.0.10", "203.0.113.8")).getHostAddress());
    }

    @Test
    void usesRightmostAddressStampedByGateway() {
        var resolver = new TrustedGatewayClientAddress("172.25.0.10");
        assertEquals("198.51.100.9", resolver.resolve(
            request("172.25.0.10", "203.0.113.8, 198.51.100.9")).getHostAddress());
    }

    @Test
    void rejectsMalformedTrustedHeaderAndBroadProxySetting() {
        var resolver = new TrustedGatewayClientAddress("172.25.0.10");
        assertThrows(IllegalArgumentException.class,
            () -> resolver.resolve(request("172.25.0.10", "attacker.invalid")));
        assertThrows(IllegalArgumentException.class,
            () -> new TrustedGatewayClientAddress("172.25.0.0/16"));
    }

    private static MockHttpServletRequest request(String peer, String forwarded) {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr(peer);
        request.addHeader("X-Forwarded-For", forwarded);
        return request;
    }
}
