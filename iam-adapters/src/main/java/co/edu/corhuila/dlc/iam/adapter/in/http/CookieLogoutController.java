package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.CookieCsrfProofService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.LogoutService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class CookieLogoutController {
    private final LogoutService logout;
    private final CookieCsrfProofService csrf;
    private final CookieOriginPolicy origins;
    private final ObjectMapper json;

    public CookieLogoutController(LogoutService logout, CookieCsrfProofService csrf,
                                  CookieOriginPolicy origins, ObjectMapper json) {
        this.logout = logout;
        this.csrf = csrf;
        this.origins = origins;
        this.json = json;
    }

    @PostMapping("/api/v1/auth/logout")
    public ResponseEntity<?> logout(@CookieValue(value = "dlc_refresh", required = false)
                                    String refresh,
                                    @RequestHeader(value = HttpHeaders.ORIGIN, required = false)
                                    String origin,
                                    @RequestHeader(value = "Sec-Fetch-Site", required = false)
                                    String fetchSite,
                                    @RequestHeader(value = "X-CSRF-Token", required = false)
                                    String proof,
                                    @RequestBody(required = false) String rawBody) {
        UUID correlationId = UUID.randomUUID();
        if (origin == null || !origins.allows(origin, fetchSite)) {
            return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Origin not allowed", correlationId);
        }
        try {
            if (rawBody == null || rawBody.length() > 1024) {
                return badRequest(correlationId);
            }
            JsonNode body = json.readTree(rawBody);
            if (body == null || !body.isObject() || body.size() > 1
                || (body.size() == 1 && (!body.has("allDevices")
                    || !body.get("allDevices").isBoolean()))) {
                return badRequest(correlationId);
            }
            boolean allDevices = body.has("allDevices") && body.get("allDevices").asBoolean();
            csrf.verify(refresh, proof, false);
            logout.logout(refresh, allDevices, correlationId);
            String expired = ResponseCookie.from("dlc_refresh", "")
                .httpOnly(true).secure(true).sameSite("Strict")
                .path("/api/v1/auth").maxAge(Duration.ZERO).build().toString();
            return ResponseEntity.noContent().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.SET_COOKIE, expired)
                .header("X-Correlation-Id", correlationId.toString()).build();
        } catch (JsonProcessingException malformed) {
            return badRequest(correlationId);
        } catch (SecurityException forbidden) {
            return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Invalid CSRF proof", correlationId);
        } catch (InvalidLoginException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED",
                "Authentication could not be completed.", correlationId);
        } catch (IllegalStateException conflict) {
            return error(HttpStatus.CONFLICT, "CONFLICT", "Logout could not be completed",
                correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Logout is temporarily unavailable", correlationId);
        }
    }

    private static ResponseEntity<Map<String, String>> badRequest(UUID correlationId) {
        return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
            "Invalid logout request", correlationId);
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code,
                                                              String message, UUID correlationId) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString())
            .body(Map.of("error", code, "message", message,
                "traceId", correlationId.toString()));
    }
}
