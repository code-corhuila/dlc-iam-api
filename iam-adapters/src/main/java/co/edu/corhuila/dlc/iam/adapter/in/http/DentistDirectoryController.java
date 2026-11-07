package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.ListDentistsService;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** GET /api/v1/auth/dentists (dlc-docs#164): Administrator and Secretary/Assistant; id and name only. */
@RestController
public final class DentistDirectoryController {
    private static final Set<String> ELIGIBLE = Set.of("ADMINISTRATOR", "SECRETARY_ASSISTANT");

    private final CurrentActorService actors;
    private final ListDentistsService dentists;

    public DentistDirectoryController(CurrentActorService actors, ListDentistsService dentists) {
        this.actors = actors;
        this.dentists = dentists;
    }

    @GetMapping("/api/v1/auth/dentists")
    public ResponseEntity<?> list(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
                                  String authorization,
                                  @RequestParam(defaultValue = "1") String page,
                                  @RequestParam(defaultValue = "20") String limit) {
        UUID correlationId = UUID.randomUUID();
        try {
            if (actors.authenticate(authorization).roles().stream().noneMatch(ELIGIBLE::contains)) {
                return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Access denied", correlationId);
            }
            var result = dentists.list(Integer.parseInt(page), Integer.parseInt(limit));
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString())
                .body(Map.of("data", result.data(), "meta", result.meta()));
        } catch (InvalidLoginException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication required", correlationId);
        } catch (IllegalArgumentException invalid) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", "Invalid dentist page", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Dentist directory unavailable",
                correlationId);
        }
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code,
            String message, UUID correlationId) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString())
            .body(Map.of("error", code, "message", message, "traceId", correlationId.toString()));
    }
}
