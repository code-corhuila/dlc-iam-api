package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.port.in.RotateRefresh;
import co.edu.corhuila.dlc.iam.application.usecase.CookieCsrfProofService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
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
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class CookieRefreshController {
    private final RotateRefresh refresh;
    private final CookieCsrfProofService csrf;
    private final CookieOriginPolicy origins;

    public CookieRefreshController(RotateRefresh refresh, CookieCsrfProofService csrf,
                                   CookieOriginPolicy origins) {
        this.refresh = refresh;
        this.csrf = csrf;
        this.origins = origins;
    }

    @PostMapping("/api/v1/auth/refresh")
    public ResponseEntity<?> rotate(@CookieValue(value = "dlc_refresh", required = false)
                                    String rawRefresh,
                                    @RequestHeader(value = HttpHeaders.ORIGIN, required = false)
                                    String origin,
                                    @RequestHeader(value = "Sec-Fetch-Site", required = false)
                                    String fetchSite,
                                    @RequestHeader(value = "X-CSRF-Token", required = false)
                                    String proof) {
        UUID correlationId = UUID.randomUUID();
        if (origin == null || !origins.allows(origin, fetchSite)) {
            return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Origin not allowed", correlationId);
        }
        try {
            // A consumed cookie can pass its session proof; the use case detects reuse
            // and commits the family revocation before returning a generic failure.
            csrf.verify(rawRefresh, proof, true);
            var result = refresh.rotate(rawRefresh, correlationId);
            String cookie = ResponseCookie.from("dlc_refresh", result.refreshToken())
                .httpOnly(true).secure(true).sameSite("Strict")
                .path("/api/v1/auth").maxAge(Duration.ofDays(7)).build().toString();
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.SET_COOKIE, cookie)
                .header("X-Correlation-Id", correlationId.toString())
                .body(Map.of("accessToken", result.accessToken(), "expiresIn", 3600,
                    "user", result.user()));
        } catch (SecurityException forbidden) {
            return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Invalid CSRF proof", correlationId);
        } catch (InvalidLoginException | IllegalArgumentException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED",
                "Authentication could not be completed.", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Refresh is temporarily unavailable", correlationId);
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
