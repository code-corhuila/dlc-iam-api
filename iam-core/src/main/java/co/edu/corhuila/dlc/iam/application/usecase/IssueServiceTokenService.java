package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.PasswordVerifier;
import co.edu.corhuila.dlc.iam.application.port.out.ServiceClientDirectory;
import co.edu.corhuila.dlc.iam.application.port.out.ServiceTokenSigner;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * ADR-020: client-credentials issuance of 15-minute service JWTs. Every requested scope must be granted for the
 * audience; unknown, disabled or wrong-secret clients are indistinguishable.
 */
public final class IssueServiceTokenService {
    static final Duration LIFETIME = Duration.ofMinutes(15);
    private static final Pattern NAME = Pattern.compile("^[a-z][a-z0-9-]{1,63}$");
    private static final Pattern SCOPE = Pattern.compile("^[a-z][a-z0-9:-]{1,127}$");

    private final ServiceClientDirectory clients;
    private final PasswordVerifier secrets;
    private final ServiceTokenSigner signer;
    private final Clock clock;

    public IssueServiceTokenService(ServiceClientDirectory clients, PasswordVerifier secrets,
                                    ServiceTokenSigner signer, Clock clock) {
        this.clients = clients;
        this.secrets = secrets;
        this.signer = signer;
        this.clock = clock;
    }

    public Issued issue(String clientId, String secret, String audience, String scope) {
        if (clientId == null || secret == null || secret.isEmpty() || audience == null
            || !NAME.matcher(audience).matches() || scope == null || scope.isBlank()) {
            throw new IllegalArgumentException("Invalid service token request");
        }
        var requested = new TreeSet<>(Arrays.asList(scope.trim().split("\s+")));
        if (requested.size() > 20 || !requested.stream().allMatch(s -> SCOPE.matcher(s).matches())) {
            throw new IllegalArgumentException("Invalid service token request");
        }
        var client = NAME.matcher(clientId).matches() ? clients.find(clientId).orElse(null) : null;
        if (client == null) {
            secrets.dummyCheck(secret);
            throw new InvalidClientException();
        }
        boolean secretMatches = false;
        for (String hash : client.secretHashes()) secretMatches |= secrets.matches(secret, hash);
        if (!secretMatches || !client.active()) throw new InvalidClientException();
        for (String one : requested) {
            if (!client.grants().contains(new ServiceClientDirectory.Grant(audience, one))) {
                throw new ScopeNotGrantedException();
            }
        }
        var now = clock.instant();
        String granted = String.join(" ", requested);
        return new Issued(signer.sign(client.clientId(), audience, granted, now, now.plus(LIFETIME)),
            LIFETIME.toSeconds(), granted);
    }

    public record Issued(String accessToken, long expiresIn, String scope) { }

    public static final class InvalidClientException extends RuntimeException {
        public InvalidClientException() {
            super("Invalid service client", null, false, false);
        }
    }

    public static final class ScopeNotGrantedException extends RuntimeException {
        public ScopeNotGrantedException() {
            super("Audience or scope not granted", null, false, false);
        }
    }
}
