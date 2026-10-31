package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import co.edu.corhuila.dlc.iam.adapter.out.security.JwtAccessTokenVerifier;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

class JwtAccessTokenVerifierTest {
    private final JwtDecoder decoder = mock(JwtDecoder.class);
    private final JwtAccessTokenVerifier verifier = new JwtAccessTokenVerifier(decoder);

    @Test
    void parsesOnlySignedStaffIdentityClaims() {
        UUID user = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        when(decoder.decode("valid")).thenReturn(token(user.toString(),
            session.toString(), List.of("ADMINISTRATOR")));
        var identity = verifier.verify("valid");
        assertEquals(user, identity.userId());
        assertEquals(session, identity.sessionId());
        assertEquals(List.of("ADMINISTRATOR"), identity.roles());
    }

    @Test
    void rejectsInvalidSignatureAndMalformedIdentityClaims() {
        when(decoder.decode("invalid")).thenThrow(new JwtException("bad signature"));
        when(decoder.decode("malformed")).thenReturn(token("not-uuid",
            UUID.randomUUID().toString(), List.of("ADMINISTRATOR")));
        when(decoder.decode("no-roles")).thenReturn(token(UUID.randomUUID().toString(),
            UUID.randomUUID().toString(), List.of()));
        assertThrows(IllegalArgumentException.class, () -> verifier.verify("invalid"));
        assertThrows(IllegalArgumentException.class, () -> verifier.verify("malformed"));
        assertThrows(IllegalArgumentException.class, () -> verifier.verify("no-roles"));
    }

    private Jwt token(String subject, String session, List<String> roles) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("ignored").header("alg", "RS256")
            .subject(subject).claim("sid", session).claim("roles", roles)
            .claim("permissions", List.of()).claim("jti", UUID.randomUUID().toString())
            .issuedAt(now).expiresAt(now.plusSeconds(3600)).build();
    }
}
