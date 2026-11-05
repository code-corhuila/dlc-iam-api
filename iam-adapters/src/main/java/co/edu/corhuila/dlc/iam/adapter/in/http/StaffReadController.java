package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.ReadStaffService;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class StaffReadController {
    private final CurrentActorService actors;
    private final ReadStaffService staff;

    public StaffReadController(CurrentActorService actors, ReadStaffService staff) {
        this.actors = actors;
        this.staff = staff;
    }

    @GetMapping("/api/v1/auth/staff/{id}")
    public ResponseEntity<?> read(@PathVariable String id,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        UUID correlationId = UUID.randomUUID();
        try {
            authorize(authorization);
            UUID staffId = UUID.fromString(id);
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString()).body(staff.read(staffId));
        } catch (InvalidLoginException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication required", correlationId);
        } catch (SecurityException denied) {
            return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Access denied", correlationId);
        } catch (IllegalArgumentException invalid) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", "Invalid staff id", correlationId);
        } catch (NoSuchElementException missing) {
            return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Staff not found", correlationId);
        } catch (IllegalStateException repair) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Staff read unavailable", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Staff read unavailable", correlationId);
        }
    }

    @GetMapping("/api/v1/auth/staff")
    public ResponseEntity<?> list(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
                                  String authorization,
                                  @RequestParam(defaultValue = "1") String page,
                                  @RequestParam(defaultValue = "20") String limit) {
        UUID correlationId = UUID.randomUUID();
        try {
            authorize(authorization);
            var result = staff.list(Integer.parseInt(page), Integer.parseInt(limit));
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString())
                .body(Map.of("data", result.data(), "meta", result.meta()));
        } catch (InvalidLoginException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication required", correlationId);
        } catch (SecurityException denied) {
            return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Access denied", correlationId);
        } catch (IllegalArgumentException invalid) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", "Invalid staff page", correlationId);
        } catch (IllegalStateException repair) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Staff read unavailable", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Staff read unavailable", correlationId);
        }
    }

    private void authorize(String authorization) {
        if (!actors.authenticate(authorization).roles().contains("ADMINISTRATOR")) {
            throw new SecurityException("Administrator required");
        }
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code,
            String message, UUID correlationId) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString())
            .body(Map.of("error", code, "message", message, "traceId", correlationId.toString()));
    }
}
