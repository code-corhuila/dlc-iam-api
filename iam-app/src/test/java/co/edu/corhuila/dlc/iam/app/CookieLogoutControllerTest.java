package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.CookieLogoutController;
import co.edu.corhuila.dlc.iam.adapter.in.http.CookieOriginPolicy;
import co.edu.corhuila.dlc.iam.application.usecase.CookieCsrfProofService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.LogoutService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class CookieLogoutControllerTest {
    private final LogoutService logout = mock(LogoutService.class);
    private final CookieCsrfProofService csrf = mock(CookieCsrfProofService.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new CookieLogoutController(
        logout, csrf, new CookieOriginPolicy("https://portal.example.test"),
        new ObjectMapper())).build();

    @Test
    void expiresCookieAfterCurrentOrAllDeviceRevocation() throws Exception {
        request("{}", "https://portal.example.test", "same-site", "proof", "cookie")
            .andExpect(status().isNoContent())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.allOf(
                org.hamcrest.Matchers.containsString("dlc_refresh="),
                org.hamcrest.Matchers.containsString("Max-Age=0"),
                org.hamcrest.Matchers.containsString("HttpOnly"),
                org.hamcrest.Matchers.containsString("Secure"),
                org.hamcrest.Matchers.containsString("SameSite=Strict"),
                org.hamcrest.Matchers.containsString("Path=/api/v1/auth"))));
        verify(csrf).verify("cookie", "proof", false);
        verify(logout).logout(eq("cookie"), eq(false), any(UUID.class));

        request("{\"allDevices\":true}", "https://portal.example.test", "same-site",
            "proof", "cookie").andExpect(status().isNoContent());
        verify(logout).logout(eq("cookie"), eq(true), any(UUID.class));
    }

    @Test
    void rejectsOriginAndMalformedBodyBeforeChangingSession() throws Exception {
        request("{}", null, "same-origin", "proof", "cookie")
            .andExpect(status().isForbidden());
        request("{}", "https://evil.example", "same-site", "proof", "cookie")
            .andExpect(status().isForbidden());
        request("{}", "https://portal.example.test", "cross-site", "proof", "cookie")
            .andExpect(status().isForbidden());
        request("{", "https://portal.example.test", "same-site", "proof", "cookie")
            .andExpect(status().isBadRequest());
        request("{\"userId\":\"other\"}", "https://portal.example.test", "same-site",
            "proof", "cookie").andExpect(status().isBadRequest());
        request("{\"allDevices\":\"true\"}", "https://portal.example.test", "same-site",
            "proof", "cookie").andExpect(status().isBadRequest());
        verifyNoInteractions(csrf, logout);
    }

    @Test
    void rejectsMissingOrWrongProofAndInvalidCookie() throws Exception {
        doThrow(new SecurityException()).when(csrf).verify("cookie", null, false);
        request("{}", "https://portal.example.test", "same-site", null, "cookie")
            .andExpect(status().isForbidden());
        doThrow(new InvalidLoginException()).when(csrf).verify("bad", "proof", false);
        request("{}", "https://portal.example.test", "same-site", "proof", "bad")
            .andExpect(status().isUnauthorized());
        verifyNoInteractions(logout);
    }

    @Test
    void failsClosedOnDatabaseOutage() throws Exception {
        doThrow(new DataAccessResourceFailureException("offline"))
            .when(csrf).verify("cookie", "proof", false);
        request("{}", "https://portal.example.test", "same-site", "proof", "cookie")
            .andExpect(status().isServiceUnavailable());
        verifyNoInteractions(logout);
    }

    private ResultActions request(String body, String origin, String fetchSite,
                                  String proof, String cookie) throws Exception {
        var request = post("/api/v1/auth/logout").contentType(MediaType.APPLICATION_JSON)
            .content(body).header("Sec-Fetch-Site", fetchSite);
        if (origin != null) request.header("Origin", origin);
        if (proof != null) request.header("X-CSRF-Token", proof);
        if (cookie != null) request.cookie(new Cookie("dlc_refresh", cookie));
        return mvc.perform(request);
    }
}
