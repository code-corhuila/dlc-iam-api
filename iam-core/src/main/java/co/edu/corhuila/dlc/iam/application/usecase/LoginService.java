package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.in.LoginUseCase;
import co.edu.corhuila.dlc.iam.application.port.out.AccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.out.LoginUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.PasswordVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.List;
import java.util.UUID;

public final class LoginService implements LoginUseCase {
    private static final Duration ACCESS_LIFETIME = Duration.ofHours(1);
    private static final Duration SESSION_LIFETIME = Duration.ofDays(7);

    private final LoginUnitOfWork unitOfWork;
    private final PasswordVerifier passwords;
    private final RefreshCredential refreshCredentials;
    private final AccessTokenIssuer tokens;
    private final Clock clock;

    public LoginService(LoginUnitOfWork unitOfWork, PasswordVerifier passwords,
                        RefreshCredential refreshCredentials, AccessTokenIssuer tokens,
                        Clock clock) {
        this.unitOfWork = unitOfWork;
        this.passwords = passwords;
        this.refreshCredentials = refreshCredentials;
        this.tokens = tokens;
        this.clock = clock;
    }

    @Override
    public LoginResult login(String email, String password, UUID correlationId) {
        if (email == null || password == null || correlationId == null) {
            throw new IllegalArgumentException("Email, password and correlation are required");
        }
        String normalizedEmail = email.strip().toLowerCase(Locale.ROOT);
        if (normalizedEmail.isBlank() || normalizedEmail.length() > 255
            || !normalizedEmail.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")
            || password.isEmpty()
            || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new IllegalArgumentException("Invalid login request");
        }
        Instant now = clock.instant();
        return unitOfWork.execute(store -> {
            var staff = store.findForUpdate(normalizedEmail);
            if (staff == null) {
                passwords.dummyCheck(password);
                throw new InvalidLoginException();
            }
            boolean validPassword = passwords.matches(password, staff.passwordHash());
            if (!validPassword || !"ACTIVE".equals(staff.status())
                || staff.verifiedAt() == null || staff.roles() == null
                || staff.roles().isEmpty() || !approvedRoles(staff)
                || staff.name() == null || staff.name().isBlank()) {
                throw new InvalidLoginException();
            }

            // The row lock and every write below are in one database transaction.
            store.resetFailures(staff.id(), now);
            UUID sessionId = UUID.randomUUID();
            UUID familyId = UUID.randomUUID();
            UUID credentialId = UUID.randomUUID();
            String deviceId = UUID.randomUUID().toString();
            String refresh = refreshCredentials.generate();
            Instant inactiveAt = now.plus(SESSION_LIFETIME);
            store.createSession(sessionId, staff.id(), deviceId, now, inactiveAt);
            store.createRefresh(familyId, sessionId, credentialId,
                refreshCredentials.hash(refresh), now, inactiveAt);
            store.appendSessionStarted(UUID.randomUUID(), correlationId, sessionId,
                staff.id(), deviceId, now, inactiveAt);
            String access = tokens.issue(staff, sessionId, now, now.plus(ACCESS_LIFETIME));
            var user = new Staff(staff.id(), staff.email(), staff.name(),
                List.copyOf(staff.roles()), staff.status(), staff.version() + 1);
            return new LoginResult(access, refresh, user);
        });
    }

    private boolean approvedRoles(LoginUnitOfWork.StaffAccount staff) {
        return staff.roles().stream().allMatch(role -> role.equals("ADMINISTRATOR")
            || role.equals("DENTIST") || role.equals("SECRETARY_ASSISTANT"));
    }
}
