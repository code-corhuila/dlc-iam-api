package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.adapter.in.http.LoginController;
import co.edu.corhuila.dlc.iam.adapter.in.http.TrustedGatewayClientAddress;
import co.edu.corhuila.dlc.iam.application.port.in.LoginUseCase;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.IpLoginLimiter;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class LoginControllerTest {
    private static final String ORIGIN = "https://portal.example.test";
    private static final String VALID = "{\"email\":\"staff@example.test\",\"password\":\"Secret123\"}";

    @Test
    void successReturnsAccessOnlyInJsonAndProtectedRefreshCookie() {
        var calls = new AtomicInteger();
        var controller = controller((email, password, correlation) -> {
            calls.incrementAndGet();
            return new LoginUseCase.LoginResult("access-secret", "refresh-secret",
                new LoginUseCase.Staff(UUID.randomUUID(), email, "Ada", List.of("DENTIST"),
                    "ACTIVE", 1));
        }, (digest, after, at, limit) -> true);
        var request = request("192.0.2.1");
        request.addHeader("X-Forwarded-For", "203.0.113.8");

        var response = controller.login(ORIGIN, VALID, request);

        assertEquals(200, response.getStatusCode().value());
        assertEquals(1, calls.get());
        assertEquals("no-store", response.getHeaders().getCacheControl());
        String cookie = response.getHeaders().getFirst("Set-Cookie");
        assertTrue(cookie.contains("dlc_refresh=refresh-secret"));
        assertTrue(cookie.contains("Secure"));
        assertTrue(cookie.contains("HttpOnly"));
        assertTrue(cookie.contains("SameSite=Strict"));
        assertTrue(cookie.contains("Path=/api/v1/auth"));
        assertFalse(response.getBody().toString().contains("refresh-secret"));
        assertEquals(3600, ((Map<?, ?>) response.getBody()).get("expiresIn"));
    }

    @Test
    void originAndMalformedBodyDoNotReachAuthentication() {
        var calls = new AtomicInteger();
        var controller = controller((email, password, correlation) -> {
            calls.incrementAndGet();
            throw new AssertionError("must not authenticate");
        }, (digest, after, at, limit) -> true);

        assertEquals(403, controller.login("https://evil.example", VALID,
            request("192.0.2.1")).getStatusCode().value());
        assertEquals(400, controller.login(ORIGIN, "{\"email\":\"x\",\"extra\":1}",
            request("192.0.2.1")).getStatusCode().value());
        assertEquals(0, calls.get());
    }

    @Test
    void invalidCredentialIsGenericAndRateLimitPrecedesPasswordCheck() {
        var calls = new AtomicInteger();
        LoginUseCase login = (email, password, correlation) -> {
            calls.incrementAndGet();
            throw new InvalidLoginException();
        };
        var controller = controller(login, (digest, after, at, limit) -> true);
        var invalid = controller.login(ORIGIN, VALID, request("192.0.2.1"));
        assertEquals(401, invalid.getStatusCode().value());
        assertEquals("UNAUTHORIZED", ((Map<?, ?>) invalid.getBody()).get("error"));
        assertEquals(null, invalid.getHeaders().getFirst("Set-Cookie"));

        var limited = controller(login, (digest, after, at, limit) -> false)
            .login(ORIGIN, VALID, request("192.0.2.1"));
        assertEquals(429, limited.getStatusCode().value());
        assertEquals(1, calls.get());
    }

    @Test
    void forwardedAddressCannotChangeTheRateLimitIdentity() {
        var firstDigest = new AtomicReference<byte[]>();
        var controller = controller((email, password, correlation) -> {
            throw new InvalidLoginException();
        }, (digest, after, at, limit) -> {
            if (firstDigest.get() == null) firstDigest.set(digest);
            else assertArrayEquals(firstDigest.get(), digest);
            return true;
        });
        var first = request("192.0.2.1");
        first.addHeader("X-Forwarded-For", "203.0.113.8");
        var second = request("192.0.2.1");
        second.addHeader("X-Forwarded-For", "198.51.100.9");

        assertEquals(401, controller.login(ORIGIN, VALID, first).getStatusCode().value());
        assertEquals(401, controller.login(ORIGIN, VALID, second).getStatusCode().value());
    }

    @Test
    void trustedGatewaySeparatesClientIpBudgets() {
        var firstDigest = new AtomicReference<byte[]>();
        var controller = controller((email, password, correlation) -> {
            throw new InvalidLoginException();
        }, (digest, after, at, limit) -> {
            if (firstDigest.get() == null) firstDigest.set(digest);
            else assertFalse(java.util.Arrays.equals(firstDigest.get(), digest));
            return true;
        }, new TrustedGatewayClientAddress("172.25.0.10"));
        var first = request("172.25.0.10");
        first.addHeader("X-Forwarded-For", "192.0.2.2, 203.0.113.8");
        var second = request("172.25.0.10");
        second.addHeader("X-Forwarded-For", "192.0.2.2, 198.51.100.9");

        assertEquals(401, controller.login(ORIGIN, VALID, first).getStatusCode().value());
        assertEquals(401, controller.login(ORIGIN, VALID, second).getStatusCode().value());
    }

    private static LoginController controller(LoginUseCase login,
                                              co.edu.corhuila.dlc.iam.application.port.out
                                                  .LoginIpAttemptWindow window) {
        return controller(login, window, new TrustedGatewayClientAddress(""));
    }

    private static LoginController controller(LoginUseCase login,
                                              co.edu.corhuila.dlc.iam.application.port.out
                                                  .LoginIpAttemptWindow window,
                                              TrustedGatewayClientAddress clientAddress) {
        return new LoginController(login,
            new IpLoginLimiter(window, new byte[32], Clock.systemUTC()),
            clientAddress, new ObjectMapper(), ORIGIN);
    }

    private static MockHttpServletRequest request(String address) {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr(address);
        return request;
    }
}
