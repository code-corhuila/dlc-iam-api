package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.ListOwnSessionsService;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.List;
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

@RestController
public final class OwnSessionListController {
    private static final Set<String> STAFF_ROLES = Set.of(
        "ADMINISTRATOR", "DENTIST", "SECRETARY_ASSISTANT");
    private final CurrentActorService actors;
    private final ListOwnSessionsService sessions;

    public OwnSessionListController(CurrentActorService actors, ListOwnSessionsService sessions) {
        this.actors = actors;
        this.sessions = sessions;
    }

    @GetMapping("/api/v1/auth/sessions")
    public ResponseEntity<?> list(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
                                  String authorization,
                                  @RequestParam(defaultValue = "1") String page,
                                  @RequestParam(defaultValue = "20") String limit) {
        UUID correlationId = UUID.randomUUID();
        try {
            var actor = actors.authenticate(authorization);
            if (actor.roles().stream().noneMatch(STAFF_ROLES::contains)) {
                return error(HttpStatus.FORBIDDEN, "FORBIDDEN", "Access denied", correlationId);
            }
            int pageNumber;
            int pageSize;
            try {
                pageNumber = Integer.parseInt(page);
                pageSize = Integer.parseInt(limit);
            } catch (NumberFormatException invalid) {
                return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                    "Invalid session page", correlationId);
            }
            var result = sessions.list(actor.userId(), actor.sessionId(), pageNumber, pageSize);
            List<SessionView> data = result.data().stream().map(SessionView::from).toList();
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Correlation-Id", correlationId.toString())
                .body(Map.of("data", data, "meta", result.meta()));
        } catch (InvalidLoginException invalid) {
            return error(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication required",
                correlationId);
        } catch (IllegalArgumentException invalid) {
            return error(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "Invalid session page", correlationId);
        } catch (DataAccessException unavailable) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE",
                "Session listing is temporarily unavailable", correlationId);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private record SessionView(UUID id, String device, Instant expiresAt, boolean current,
                               Instant createdAt, long version, Instant lastUserActivityAt) {
        static SessionView from(ListOwnSessionsService.Session session) {
            return new SessionView(session.id(), session.device(), session.expiresAt(),
                session.current(), session.createdAt(), session.version(),
                session.lastUserActivityAt());
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
