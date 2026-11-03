package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.port.in.LoginUseCase;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.IpLoginLimiter;
import co.edu.corhuila.dlc.iam.application.usecase.TooManyLoginAttemptsException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class LoginController {
    private final LoginUseCase login;
    private final IpLoginLimiter limiter;
    private final ObjectMapper json;
    private final String allowedOrigin;

    public LoginController(LoginUseCase login, IpLoginLimiter limiter, ObjectMapper json,
                           @Value("${IAM_AUTH_ALLOWED_ORIGIN}") String allowedOrigin) {
        if (allowedOrigin == null || allowedOrigin.isBlank() || allowedOrigin.contains("*")) {
            throw new IllegalArgumentException("An exact login Origin is required");
        }
        this.login = login;
        this.limiter = limiter;
        this.json = json;
        this.allowedOrigin = allowedOrigin;
    }

    @PostMapping("/api/v1/auth/login")
    public ResponseEntity<?> login(@RequestHeader(value = HttpHeaders.ORIGIN, required = false)
                                   String origin,
                                   @RequestBody(required = false) String rawBody,
                                   HttpServletRequest request) {
        UUID correlationId = UUID.randomUUID();
        if (!allowedOrigin.equals(origin)) {
            return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Origin not allowed", correlationId);
        }
        try {
            // Only the connection peer is trusted. Forwarded headers need a separate proxy policy.
            limiter.checkAndRecord(peer(request.getRemoteAddr()));
            JsonNode body = rawBody == null || rawBody.length() > 4096
                ? null : json.readTree(rawBody);
            if (body == null || !body.isObject() || body.size() != 2
                || !body.has("email") || !body.get("email").isTextual()
                || !body.has("password") || !body.get("password").isTextual()) {
                return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                    "Invalid login request", correlationId);
            }
            var result = login.login(body.get("email").asText(),
                body.get("password").asText(), correlationId);
            String cookie = ResponseCookie.from("dlc_refresh", result.refreshToken())
                .httpOnly(true).secure(true).sameSite("Strict")
                .path("/api/v1/auth").maxAge(Duration.ofDays(7)).build().toString();
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.SET_COOKIE, cookie)
                .header("X-Correlation-Id", correlationId.toString())
                .body(Map.of("accessToken", result.accessToken(), "expiresIn", 3600,
                    "user", result.user()));
        } catch (TooManyLoginAttemptsException limited) {
            return error(HttpStatus.TOO_MANY_REQUESTS, "TOO_MANY_REQUESTS",
                "Too many login attempts", correlationId);
        } catch (InvalidLoginException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED",
                "Authentication could not be completed.", correlationId);
        } catch (IllegalArgumentException | JsonProcessingException invalid) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid login request", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Authentication is temporarily unavailable", correlationId);
        }
    }

    private static InetAddress peer(String remoteAddress) {
        if (remoteAddress == null || !remoteAddress.matches("[0-9a-fA-F:.]+")) {
            throw new IllegalArgumentException("Invalid connection address");
        }
        try {
            return InetAddress.getByName(remoteAddress);
        } catch (UnknownHostException invalid) {
            throw new IllegalArgumentException("Invalid connection address", invalid);
        }
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code,
                                                              String message, UUID correlationId) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString())
            .body(Map.of("error", code, "message", message,
                "traceId", correlationId.toString()));
    }
}
