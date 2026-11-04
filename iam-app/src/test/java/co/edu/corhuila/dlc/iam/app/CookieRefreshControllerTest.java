package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.CookieOriginPolicy;
import co.edu.corhuila.dlc.iam.adapter.in.http.CookieRefreshController;
import co.edu.corhuila.dlc.iam.application.port.in.RotateRefresh;
import co.edu.corhuila.dlc.iam.application.usecase.CookieCsrfProofService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import jakarta.servlet.http.Cookie;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class CookieRefreshControllerTest {
    private final RotateRefresh refresh = mock(RotateRefresh.class);
    private final CookieCsrfProofService csrf = mock(CookieCsrfProofService.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new CookieRefreshController(
        refresh, csrf, new CookieOriginPolicy("https://portal.example.test"))).build();

    @Test
    void rotatesCookieAndReturnsOnlyAccessTokenAndUser() throws Exception {
        when(refresh.rotate(eq("old-cookie"), any(UUID.class))).thenReturn(
            new RotateRefresh.Result("signed-access", "new-cookie",
                new RotateRefresh.Staff(UUID.randomUUID(), "ada@example.test", "Ada",
                    List.of("DENTIST"), "ACTIVE", 3)));
        request("https://portal.example.test", "same-site", "proof", "old-cookie")
            .andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.allOf(
                org.hamcrest.Matchers.containsString("dlc_refresh=new-cookie"),
                org.hamcrest.Matchers.containsString("HttpOnly"),
                org.hamcrest.Matchers.containsString("Secure"),
                org.hamcrest.Matchers.containsString("SameSite=Strict"),
                org.hamcrest.Matchers.containsString("Path=/api/v1/auth"))))
            .andExpect(jsonPath("$.accessToken").value("signed-access"))
            .andExpect(jsonPath("$.expiresIn").value(3600))
            .andExpect(jsonPath("$.refreshToken").doesNotExist());
        verify(csrf).verify("old-cookie", "proof", true);
        verify(refresh).rotate(eq("old-cookie"), any(UUID.class));
    }

    @Test
    void rejectsMissingOrDisallowedOriginBeforeCredentials() throws Exception {
        request(null, "same-origin", "proof", "old-cookie")
            .andExpect(status().isForbidden());
        request("https://evil.example", "same-site", "proof", "old-cookie")
            .andExpect(status().isForbidden());
        request("https://portal.example.test", "cross-site", "proof", "old-cookie")
            .andExpect(status().isForbidden());
        verifyNoInteractions(csrf, refresh);
    }

    @Test
    void rejectsCsrfAndReportsReuseAsGenericAuthenticationFailure() throws Exception {
        doThrow(new SecurityException()).when(csrf).verify("old-cookie", null, true);
        request("https://portal.example.test", "same-site", null, "old-cookie")
            .andExpect(status().isForbidden());
        verifyNoInteractions(refresh);

        when(refresh.rotate(eq("old-cookie"), any(UUID.class)))
            .thenThrow(new InvalidLoginException());
        request("https://portal.example.test", "same-site", "proof", "old-cookie")
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("UNAUTHORIZED"))
            .andExpect(header().doesNotExist("Set-Cookie"));
        verify(csrf).verify("old-cookie", "proof", true);
        verify(refresh).rotate(eq("old-cookie"), any(UUID.class));
    }

    @Test
    void databaseOutageFailsClosed() throws Exception {
        doThrow(new DataAccessResourceFailureException("offline"))
            .when(csrf).verify("old-cookie", "proof", true);
        request("https://portal.example.test", "same-site", "proof", "old-cookie")
            .andExpect(status().isServiceUnavailable());
        verifyNoInteractions(refresh);
    }

    private ResultActions request(String origin, String fetchSite, String proof,
                                  String cookie) throws Exception {
        var request = post("/api/v1/auth/refresh").header("Sec-Fetch-Site", fetchSite);
        if (origin != null) request.header("Origin", origin);
        if (proof != null) request.header("X-CSRF-Token", proof);
        if (cookie != null) request.cookie(new Cookie("dlc_refresh", cookie));
        return mvc.perform(request);
    }
}
