package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.PasswordHasher;
import co.edu.corhuila.dlc.iam.application.port.out.RegistrationRequestProof;
import co.edu.corhuila.dlc.iam.application.port.out.RegistrationUnitOfWork;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.ConcurrentModificationException;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

public final class RegisterStaffService {
    private static final Set<String> ROLES = Set.of("DENTIST", "SECRETARY_ASSISTANT");
    private final RegistrationUnitOfWork unitOfWork;
    private final PasswordHasher passwords;
    private final RegistrationRequestProof proofs;
    private final Clock clock;

    public RegisterStaffService(RegistrationUnitOfWork unitOfWork, PasswordHasher passwords,
                                RegistrationRequestProof proofs, Clock clock) {
        this.unitOfWork = unitOfWork;
        this.passwords = passwords;
        this.proofs = proofs;
        this.clock = clock;
    }

    public RegistrationUnitOfWork.Staff register(UUID actorId, String email, String password,
                                                 String name, String role, UUID idempotencyKey,
                                                 UUID correlationId) {
        if (actorId == null || email == null || password == null || name == null || role == null
            || idempotencyKey == null || correlationId == null || !ROLES.contains(role)
            || name.isBlank() || !name.equals(name.strip()) || name.length() > 100
            || password.length() < 8 || password.length() > 72
            || password.getBytes(StandardCharsets.UTF_8).length > 72
            || password.chars().noneMatch(Character::isUpperCase)
            || password.chars().noneMatch(Character::isDigit)) {
            throw new IllegalArgumentException("Invalid staff registration");
        }
        String normalizedEmail = email.strip().toLowerCase(Locale.ROOT);
        if (normalizedEmail.length() > 255 || !normalizedEmail.matches("[^@\\s]+@[^@\\s]+\\.[^@\\s]+")) {
            throw new IllegalArgumentException("Invalid staff registration");
        }
        return unitOfWork.execute(store -> {
            if (!store.activeAdministratorForUpdate(actorId)) {
                throw new SecurityException("Administrator required");
            }
            byte[] proof = proofs.prove(normalizedEmail, password, name, role);
            var attempt = store.findAttempt(idempotencyKey);
            if (attempt != null) {
                if (!actorId.equals(attempt.actorId())
                    || !MessageDigest.isEqual(proof, attempt.proof())) {
                    throw new ConcurrentModificationException("Idempotency key reused");
                }
                return attempt.staff();
            }
            if (store.emailExists(normalizedEmail)) {
                throw new ConcurrentModificationException("Staff email already exists");
            }
            UUID userId = UUID.randomUUID();
            // PostgreSQL stores timestamptz at microsecond precision; replay must match the first response.
            var at = clock.instant().truncatedTo(ChronoUnit.MICROS);
            String passwordHash = passwords.hash(password);
            store.createStaff(userId, actorId, normalizedEmail, passwordHash, name, role, at);
            store.appendAudit(userId, actorId, correlationId, at);
            store.appendUserRegistered(userId, actorId, correlationId, at);
            var staff = new RegistrationUnitOfWork.Staff(userId, normalizedEmail, name, role,
                "PENDING_VERIFICATION", at, 1);
            store.rememberAttempt(idempotencyKey, actorId, proof, staff);
            return staff;
        });
    }
}
