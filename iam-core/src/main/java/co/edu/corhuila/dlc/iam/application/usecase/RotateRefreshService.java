package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.in.RotateRefresh;
import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshRotationUnitOfWork;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public final class RotateRefreshService implements RotateRefresh {
    private static final Duration ACCESS_LIFETIME = Duration.ofHours(1);
    private static final Duration REFRESH_LIFETIME = Duration.ofDays(7);
    private static final Set<String> STAFF_ROLES = Set.of(
        "ADMINISTRATOR", "DENTIST", "SECRETARY_ASSISTANT");

    private final RefreshRotationUnitOfWork unitOfWork;
    private final RefreshCredential refreshCredentials;
    private final AccessTokenIssuer accessTokens;
    private final Clock clock;

    public RotateRefreshService(RefreshRotationUnitOfWork unitOfWork,
                                RefreshCredential refreshCredentials,
                                AccessTokenIssuer accessTokens, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.refreshCredentials = refreshCredentials;
        this.accessTokens = accessTokens;
        this.clock = clock;
    }

    @Override
    public Result rotate(String rawRefresh, UUID correlationId) {
        if (rawRefresh == null || rawRefresh.isBlank() || rawRefresh.length() > 512
            || correlationId == null) {
            throw new IllegalArgumentException("Invalid refresh request");
        }
        Instant now = clock.instant();
        String tokenHash = refreshCredentials.hash(rawRefresh);
        Result result = unitOfWork.execute(store -> {
            var credential = store.findForUpdate(tokenHash);
            if (credential == null) return null;
            if (credential.consumedAt() != null || credential.revokedAt() != null) {
                if (credential.familyRevokedAt() == null) {
                    store.revokeReusedFamily(credential.familyId(), credential.sessionId(),
                        credential.staff().id(), correlationId, now);
                }
                return null;
            }
            if (credential.familyRevokedAt() != null || credential.sessionRevokedAt() != null
                || !credential.expiresAt().isAfter(now)
                || !credential.inactivityExpiresAt().isAfter(now)
                || !eligible(credential.staff())) return null;

            String replacement = refreshCredentials.generate();
            UUID replacementId = UUID.randomUUID();
            if (!store.rotate(credential.id(), replacementId,
                refreshCredentials.hash(replacement), now, now.plus(REFRESH_LIFETIME))) return null;
            String access = accessTokens.issue(credential.staff(), credential.sessionId(),
                now, now.plus(ACCESS_LIFETIME));
            var staff = credential.staff();
            return new Result(access, replacement,
                new Staff(staff.id(), staff.email(), staff.name(), List.copyOf(staff.roles()),
                    staff.status(), staff.version()));
        });
        // A reuse revocation must commit before the generic failure leaves this use case.
        if (result == null) throw new InvalidLoginException();
        return result;
    }

    private static boolean eligible(LoginUnitOfWork.StaffAccount staff) {
        return staff != null && "ACTIVE".equals(staff.status())
            && staff.verifiedAt() != null && staff.name() != null && !staff.name().isBlank()
            && staff.roles() != null && !staff.roles().isEmpty()
            && staff.roles().stream().allMatch(STAFF_ROLES::contains);
    }
}
