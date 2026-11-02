package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.PasswordResetController;
import co.edu.corhuila.dlc.iam.application.port.in.ResetPassword;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidRecoveryChallengeException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class PasswordResetControllerTest {
    private final FakeReset reset = new FakeReset();
    private final org.springframework.test.web.servlet.MockMvc mvc = MockMvcBuilders
        .standaloneSetup(new PasswordResetController(reset)).build();

    @Test
    void resetsWithoutReturningCredentialsAndPropagatesCorrelation() throws Exception {
        mvc.perform(post("/api/v1/auth/password-resets").contentType("application/json")
                .content("{\"token\":\"opaque-secret\",\"password\":\"ValidPass1\"}"))
            .andExpect(status().isOk())
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.message").value("Password reset completed"))
            .andExpect(jsonPath("$.token").doesNotExist())
            .andExpect(jsonPath("$.password").doesNotExist());
        assertEquals("opaque-secret", reset.token);
        assertEquals("ValidPass1", reset.password);
        assertNotNull(reset.correlationId);
    }

    @Test
    void invalidBodiesNeverReachUseCase() throws Exception {
        for (String body : new String[] {"{}", "{\"token\":\"x\"}",
            "{\"token\":\"x\",\"password\":\"weak\"}",
            "{",
            "{\"token\":\"x\",\"password\":\"ValidPass1\",\"email\":\"x\"}"}) {
            mvc.perform(post("/api/v1/auth/password-resets")
                    .contentType("application/json").content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
        }
        assertEquals(0, reset.calls);
    }

    @Test
    void consumedOrExpiredChallengeHasOneGenericConflict() throws Exception {
        reset.failure = new InvalidRecoveryChallengeException();
        mvc.perform(post("/api/v1/auth/password-resets").contentType("application/json")
                .content("{\"token\":\"opaque-secret\",\"password\":\"ValidPass1\"}"))
            .andExpect(status().isConflict())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.error").value("INVALID_CHALLENGE"))
            .andExpect(jsonPath("$.message").value("Invalid or expired recovery token"));
    }

    @Test
    void unavailableDatabaseIsRetryableWithoutExposingCause() throws Exception {
        reset.failure = new DataAccessResourceFailureException("database down");
        mvc.perform(post("/api/v1/auth/password-resets").contentType("application/json")
                .content("{\"token\":\"opaque-secret\",\"password\":\"ValidPass1\"}"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.error").value("SERVICE_UNAVAILABLE"))
            .andExpect(jsonPath("$.message").value("Password reset is temporarily unavailable"));
    }

    private static final class FakeReset implements ResetPassword {
        String token;
        String password;
        UUID correlationId;
        RuntimeException failure;
        int calls;

        @Override
        public void reset(String token, String password, UUID correlationId) {
            calls++;
            this.token = token;
            this.password = password;
            this.correlationId = correlationId;
            if (failure != null) throw failure;
        }
    }
}
