package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.LogoutUnitOfWork;
import co.edu.corhuila.dlc.iam.application.port.out.RefreshCredential;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Stateless, session-bound CSRF proof for cookie-authenticated IAM operations. */
public final class CookieCsrfProofService {
    private final LogoutUnitOfWork sessions;
    private final RefreshCredential credentials;
    private final byte[] key;
    private final Clock clock;
    private final SecureRandom random;

    public CookieCsrfProofService(LogoutUnitOfWork sessions, RefreshCredential credentials,
                                  byte[] key, Clock clock, SecureRandom random) {
        if (sessions == null || credentials == null || key == null || key.length < 32
            || clock == null || random == null) {
            throw new IllegalArgumentException("A 256-bit CSRF key is required");
        }
        this.sessions = sessions;
        this.credentials = credentials;
        this.key = key.clone();
        this.clock = clock;
        this.random = random;
    }

    public String issue(String rawRefresh) {
        UUID sessionId = session(rawRefresh, false);
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        var base64 = Base64.getUrlEncoder().withoutPadding();
        return base64.encodeToString(nonce) + "." + base64.encodeToString(mac(sessionId, nonce));
    }

    /** Consumed credentials may reach the rotation use case so reuse revokes the family. */
    public void verify(String rawRefresh, String proof, boolean allowConsumed) {
        if (proof == null || proof.length() > 512) throw new SecurityException("Invalid CSRF proof");
        String[] parts = proof.split("\\.", -1);
        if (parts.length != 2) throw new SecurityException("Invalid CSRF proof");
        byte[] nonce;
        byte[] supplied;
        try {
            nonce = Base64.getUrlDecoder().decode(parts[0]);
            supplied = Base64.getUrlDecoder().decode(parts[1]);
        } catch (IllegalArgumentException malformed) {
            throw new SecurityException("Invalid CSRF proof", malformed);
        }
        if (nonce.length != 32 || supplied.length != 32) {
            throw new SecurityException("Invalid CSRF proof");
        }
        UUID sessionId = session(rawRefresh, allowConsumed);
        if (!MessageDigest.isEqual(mac(sessionId, nonce), supplied)) {
            throw new SecurityException("Invalid CSRF proof");
        }
    }

    private UUID session(String rawRefresh, boolean allowConsumed) {
        if (rawRefresh == null || rawRefresh.isBlank() || rawRefresh.length() > 512) {
            throw new InvalidLoginException();
        }
        String hash = credentials.hash(rawRefresh);
        var now = clock.instant();
        return sessions.execute(store -> {
            var credential = store.findForUpdate(hash);
            if (credential == null || credential.revokedAt() != null
                || credential.familyRevokedAt() != null || credential.sessionRevokedAt() != null
                || (!allowConsumed && credential.consumedAt() != null)
                || !credential.expiresAt().isAfter(now)
                || !credential.inactivityExpiresAt().isAfter(now)) {
                throw new InvalidLoginException();
            }
            return credential.sessionId();
        });
    }

    private byte[] mac(UUID sessionId, byte[] nonce) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] input = ByteBuffer.allocate(48).putLong(sessionId.getMostSignificantBits())
                .putLong(sessionId.getLeastSignificantBits()).put(nonce).array();
            return hmac.doFinal(input);
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("Cannot create CSRF proof", failure);
        }
    }
}
