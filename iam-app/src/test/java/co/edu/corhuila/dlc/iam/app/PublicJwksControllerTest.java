package co.edu.corhuila.dlc.iam.app;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.PublicJwksController;
import co.edu.corhuila.dlc.iam.adapter.out.security.RsaAccessTokenIssuer;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class PublicJwksControllerTest {
    @Test
    void publishesCurrentAndPreviousPublicKeysWithoutPrivateMaterial() throws Exception {
        var issuer = mock(RsaAccessTokenIssuer.class);
        when(issuer.publicJwks()).thenReturn(List.of(
            Map.of("kty", "RSA", "kid", "current", "use", "sig", "alg", "RS256",
                "n", "current-modulus", "e", "AQAB"),
            Map.of("kty", "RSA", "kid", "previous", "use", "sig", "alg", "RS256",
                "n", "previous-modulus", "e", "AQAB")));
        var mvc = MockMvcBuilders.standaloneSetup(new PublicJwksController(issuer)).build();

        mvc.perform(get("/api/v1/auth/jwks"))
            .andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.keys.length()").value(2))
            .andExpect(jsonPath("$.keys[0].kid").value("current"))
            .andExpect(jsonPath("$.keys[1].kid").value("previous"))
            .andExpect(jsonPath("$.keys[0].d").doesNotExist())
            .andExpect(jsonPath("$.keys[1].d").doesNotExist());
    }
}
