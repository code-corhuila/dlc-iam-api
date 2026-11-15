package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.CookieCsrfProofService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class CookieCsrfController {
    private final CookieCsrfProofService proofs;
    private final CookieOriginPolicy origins;

    public CookieCsrfController(CookieCsrfProofService proofs, CookieOriginPolicy origins) {
        this.proofs = proofs;
        this.origins = origins;
    }

    @GetMapping("/api/v1/auth/csrf")
    public ResponseEntity<?> read(@CookieValue(value = "dlc_refresh", required = false)
                                  String refresh,
                                  @RequestHeader(value = HttpHeaders.ORIGIN, required = false)
                                  String origin,
                                  @RequestHeader(value = "Sec-Fetch-Site", required = false)
                                  String fetchSite) {
        UUID correlationId = UUID.randomUUID();
        if (!origins.allows(origin, fetchSite)) {
            return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Origin not allowed", correlationId);
        }
        try {
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString())
                .body(Map.of("csrfToken", proofs.issue(refresh)));
        } catch (InvalidLoginException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED",
                "Authentication required", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "CSRF proof is temporarily unavailable", correlationId);
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
