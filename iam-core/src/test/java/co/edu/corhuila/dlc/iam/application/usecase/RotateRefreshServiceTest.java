package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshRotationUnitOfWork;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class RotateRefreshServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-02T10:00:00Z");
    private static final UUID USER = UUID.randomUUID();
    private static final UUID SESSION = UUID.randomUUID();
    private static final UUID FAMILY = UUID.randomUUID();
    private static final UUID CREDENTIAL = UUID.randomUUID();
    private final FakeStore store = new FakeStore();
    private final RotateRefreshService service = new RotateRefreshService(store,
        new RefreshCredential() {
            public String generate() { return "new-secret"; }
            public String hash(String raw) { return "sha256:" + raw; }
        }, (staff, sessionId, issuedAt, expiresAt) -> {
            assertEquals(USER, staff.id());
            assertEquals(SESSION, sessionId);
            assertEquals(NOW.plusSeconds(3600), expiresAt);
            return "signed-access";
        }, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void rotatesEligibleCredentialWithoutExtendingUserActivity() {
        store.credential = credential(staff("ACTIVE", List.of("DENTIST")));
        var result = service.rotate("old-secret", UUID.randomUUID());
        assertEquals("signed-access", result.accessToken());
        assertEquals("new-secret", result.refreshToken());
        assertEquals(USER, result.user().id());
        assertEquals(1, store.rotations);
        assertEquals("sha256:old-secret", store.lookupHash);
        assertEquals("sha256:new-secret", store.replacementHash);
        assertEquals(NOW.plusSeconds(7 * 86400), store.replacementExpiry);
        assertEquals(0, store.reuseRevocations);
        assertTrue(store.completed);
    }

    @Test
    void consumedCredentialRevokesFamilyAndCommitsBeforeGenericFailure() {
        store.credential = credential(staff("ACTIVE", List.of("DENTIST")));
        service.rotate("old-secret", UUID.randomUUID());
        assertThrows(InvalidLoginException.class,
            () -> service.rotate("old-secret", UUID.randomUUID()));
        assertEquals(1, store.rotations);
        assertEquals(1, store.reuseRevocations);
        assertEquals(FAMILY, store.revokedFamily);
        assertTrue(store.completed);
    }

    @Test
    void missingExpiredIneligibleAndAlreadyRevokedCredentialsFailGenerically() {
        assertThrows(InvalidLoginException.class,
            () -> service.rotate("unknown", UUID.randomUUID()));
        store.credential = credential(staff("LOCKED", List.of("DENTIST")));
        assertThrows(InvalidLoginException.class,
            () -> service.rotate("old-secret", UUID.randomUUID()));
        store.credential = credential(staff("ACTIVE", List.of("PATIENT")));
        assertThrows(InvalidLoginException.class,
            () -> service.rotate("old-secret", UUID.randomUUID()));
        store.credential = new RefreshRotationUnitOfWork.Credential(CREDENTIAL, FAMILY, SESSION,
            NOW, null, null, null, null, NOW.plusSeconds(60),
            staff("ACTIVE", List.of("DENTIST")));
        assertThrows(InvalidLoginException.class,
            () -> service.rotate("old-secret", UUID.randomUUID()));
        store.credential = new RefreshRotationUnitOfWork.Credential(CREDENTIAL, FAMILY, SESSION,
            NOW.plusSeconds(60), null, null, NOW, null, NOW.plusSeconds(60),
            staff("ACTIVE", List.of("DENTIST")));
        assertThrows(InvalidLoginException.class,
            () -> service.rotate("old-secret", UUID.randomUUID()));
        assertEquals(0, store.rotations);
        assertEquals(0, store.reuseRevocations);
    }

    @Test
    void revokedCredentialTriggersOneReuseRevocationButInactiveSessionCannotRotate() {
        store.credential = new RefreshRotationUnitOfWork.Credential(CREDENTIAL, FAMILY, SESSION,
            NOW.plusSeconds(60), null, NOW, null, null, NOW.plusSeconds(60),
            staff("ACTIVE", List.of("DENTIST")));
        assertThrows(InvalidLoginException.class,
            () -> service.rotate("old-secret", UUID.randomUUID()));
        assertEquals(1, store.reuseRevocations);
        assertTrue(store.completed);
        store.credential = new RefreshRotationUnitOfWork.Credential(CREDENTIAL, FAMILY, SESSION,
            NOW.plusSeconds(60), null, null, null, null, NOW,
            staff("ACTIVE", List.of("DENTIST")));
        assertThrows(InvalidLoginException.class,
            () -> service.rotate("old-secret", UUID.randomUUID()));
        assertEquals(0, store.rotations);
        assertEquals(1, store.reuseRevocations);
    }

    @Test
    void invalidInputCannotReachStore() {
        assertThrows(IllegalArgumentException.class, () -> service.rotate("", UUID.randomUUID()));
        assertThrows(IllegalArgumentException.class, () -> service.rotate("x", null));
        assertEquals(0, store.lookups);
    }

    private static RefreshRotationUnitOfWork.Credential credential(LoginUnitOfWork.StaffAccount staff) {
        return new RefreshRotationUnitOfWork.Credential(CREDENTIAL, FAMILY, SESSION,
            NOW.plusSeconds(60), null, null, null, null, NOW.plusSeconds(60), staff);
    }

    private static LoginUnitOfWork.StaffAccount staff(String status, List<String> roles) {
        return new LoginUnitOfWork.StaffAccount(USER, "ada@example.test", "Ada", "hash",
            status, NOW, 0, null, 5, roles);
    }

    private static final class FakeStore implements RefreshRotationUnitOfWork,
                                                    RefreshRotationUnitOfWork.Store {
        RefreshRotationUnitOfWork.Credential credential;
        String lookupHash;
        String replacementHash;
        Instant replacementExpiry;
        UUID revokedFamily;
        int lookups;
        int rotations;
        int reuseRevocations;
        boolean completed;

        public <T> T execute(Function<Store, T> operation) {
            completed = false;
            T result = operation.apply(this);
            completed = true;
            return result;
        }

        public RefreshRotationUnitOfWork.Credential findForUpdate(String tokenHash) {
            lookups++;
            lookupHash = tokenHash;
            return credential;
        }

        public boolean rotate(UUID credentialId, UUID replacementId, String replacementHash,
                              Instant at, Instant expiresAt) {
            rotations++;
            this.replacementHash = replacementHash;
            this.replacementExpiry = expiresAt;
            credential = new RefreshRotationUnitOfWork.Credential(credential.id(), FAMILY,
                SESSION, credential.expiresAt(), at, null, null, null,
                credential.inactivityExpiresAt(), credential.staff());
            return true;
        }

        public void revokeReusedFamily(UUID familyId, UUID sessionId, UUID userId,
                                       UUID correlationId, Instant at) {
            reuseRevocations++;
            revokedFamily = familyId;
        }
    }
}
