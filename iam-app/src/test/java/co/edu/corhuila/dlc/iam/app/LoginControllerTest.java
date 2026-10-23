package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.LoginController;
import co.edu.corhuila.dlc.iam.adapter.in.http.LoginErrors;
import co.edu.corhuila.dlc.iam.adapter.out.security.RsaAccessTokenIssuer;
import co.edu.corhuila.dlc.iam.application.port.in.LoginUseCase;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.LoginRateLimitedException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.CannotCreateTransactionException;

class LoginControllerTest {
    private final LoginUseCase login = mock(LoginUseCase.class);
    private final RsaAccessTokenIssuer signing = mock(RsaAccessTokenIssuer.class);
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new LoginController(login, signing))
            .setControllerAdvice(new LoginErrors()).build();
    }

    @Test
    void loginReturnsProtectedCookieAndMinimizedJson() throws Exception {
        var user = new LoginUseCase.Staff(UUID.randomUUID(), "staff@example.test",
            "Example Staff", List.of("DENTIST"), "ACTIVE", 2);
        when(login.login(anyString(), anyString(), any(UUID.class), anyString()))
            .thenReturn(new LoginUseCase.LoginResult("signed-access", "opaque-secret", user));

        mvc.perform(post("/api/v1/auth/login")
                .with(request -> { request.setRemoteAddr("192.0.2.4"); return request; })
                .header("X-Forwarded-For", "198.51.100.9")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"staff@example.test\",\"password\":\"valid\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").value("signed-access"))
            .andExpect(jsonPath("$.expiresIn").value(3600))
            .andExpect(jsonPath("$.user.name").value("Example Staff"))
            .andExpect(jsonPath("$.refreshToken").doesNotExist())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(header().string("Set-Cookie",
                org.hamcrest.Matchers.allOf(
                    org.hamcrest.Matchers.containsString("dlc_refresh=opaque-secret"),
                    org.hamcrest.Matchers.containsString("HttpOnly"),
                    org.hamcrest.Matchers.containsString("Secure"),
                    org.hamcrest.Matchers.containsString("SameSite=Strict"))));
        verify(login).login(eq("staff@example.test"), eq("valid"),
            any(UUID.class), eq("192.0.2.4"));
    }

    @Test
    void invalidCredentialsAndDatabaseFailureDoNotRevealAccountState() throws Exception {
        when(login.login(anyString(), anyString(), any(UUID.class), anyString()))
            .thenThrow(new InvalidLoginException())
            .thenThrow(new DataAccessResourceFailureException("private database detail"))
            .thenThrow(new CannotCreateTransactionException("private host detail"));
        String request = "{\"email\":\"staff@example.test\",\"password\":\"wrong\"}";
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(request))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value("Authentication could not be completed."))
            .andExpect(header().string("WWW-Authenticate", "Bearer realm=\"di-lucca\""));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(request))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.message").value(
                "Authentication service is temporarily unavailable"));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(request))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.message").value(
                "Authentication service is temporarily unavailable"));
    }

    @Test
    void rateLimitReturns429WithoutAccountDetails() throws Exception {
        when(login.login(anyString(), anyString(), any(UUID.class), anyString()))
            .thenThrow(new LoginRateLimitedException());
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"staff@example.test\",\"password\":\"wrong\"}"))
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.error").value("TOO_MANY_REQUESTS"))
            .andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    void jwksContainsOnlyPublicComponents() throws Exception {
        when(signing.publicJwks()).thenReturn(List.of(Map.of("kty", "RSA", "kid", "current",
            "use", "sig", "alg", "RS256", "n", "public-modulus", "e", "AQAB")));
        mvc.perform(get("/api/v1/auth/jwks"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys[0].kid").value("current"))
            .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }
}
