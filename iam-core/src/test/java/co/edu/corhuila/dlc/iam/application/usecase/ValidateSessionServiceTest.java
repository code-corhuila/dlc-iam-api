package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.application.port.out.SessionSnapshotReader;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ValidateSessionServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-06T12:00:00Z");

    @Test
    void rejectsOldOrUnapprovedPermissionClaimsEvenWithCurrentSessionAndRoles() {
        var user = UUID.randomUUID();
        var session = UUID.randomUUID();
        var state = new SessionSnapshotReader.Snapshot("ACTIVE", NOW.minusSeconds(60),
            null, null, NOW.plusSeconds(3600), List.of("ADMINISTRATOR"));
        var service = new ValidateSessionService((id, sid) -> state,
            Clock.fixed(NOW, ZoneOffset.UTC));
        var approved = List.of("clinical:read", "patients:read", "patients:register", "patients:write");
        assertTrue(service.active(user, session, List.of("ADMINISTRATOR"), approved));
        assertFalse(service.active(user, session, List.of("ADMINISTRATOR"),
            List.of("patients:read", "clinical:read")));
        assertFalse(service.active(user, session, List.of("ADMINISTRATOR"),
            List.of("patients:read", "patients:register", "patients:write", "clinical:write")));
        assertFalse(service.active(user, session, List.of("ADMINISTRATOR"), List.of()));
        assertFalse(service.active(user, session, List.of("ADMINISTRATOR"),
            List.of("patients:read", "patients:read", "patients:register", "patients:write")));
    }
}
