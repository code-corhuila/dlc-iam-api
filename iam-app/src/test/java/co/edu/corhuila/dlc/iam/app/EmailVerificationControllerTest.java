package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.EmailVerificationController;
import co.edu.corhuila.dlc.iam.application.port.in.VerifyStaffEmail;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidVerificationChallengeException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class EmailVerificationControllerTest {
    private final FakeVerification verification = new FakeVerification();
    private final org.springframework.test.web.servlet.MockMvc mvc = MockMvcBuilders
        .standaloneSetup(new EmailVerificationController(verification)).build();

    @Test
    void verifiesTokenWithCorrelationAndDoesNotReturnIt() throws Exception {
        mvc.perform(post("/api/v1/auth/email-verifications")
                .contentType("application/json").content("{\"token\":\"opaque-secret\"}"))
            .andExpect(status().isOk())
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.message").value("Email verified"))
            .andExpect(jsonPath("$.token").doesNotExist());
        assertEquals("opaque-secret", verification.token);
        assertNotNull(verification.correlationId);
    }

    @Test
    void rejectsMissingOrUnexpectedFieldsBeforeCallingUseCase() throws Exception {
        mvc.perform(post("/api/v1/auth/email-verifications")
                .contentType("application/json").content("{\"token\":\"x\",\"email\":\"a@example.test\"}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
        mvc.perform(post("/api/v1/auth/email-verifications")
                .contentType("application/json").content("{}"))
            .andExpect(status().isBadRequest());
        assertEquals(0, verification.calls);
    }

    @Test
    void expiredAndUnknownTokensHaveTheSameGenericConflict() throws Exception {
        verification.failure = new InvalidVerificationChallengeException();
        mvc.perform(post("/api/v1/auth/email-verifications")
                .contentType("application/json").content("{\"token\":\"opaque-secret\"}"))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.error").value("INVALID_CHALLENGE"))
            .andExpect(jsonPath("$.message").value("Invalid or expired verification token"));
    }

    @Test
    void unavailableDatabaseReturnsRetryableServiceFailure() throws Exception {
        verification.failure = new DataAccessResourceFailureException("database down");
        mvc.perform(post("/api/v1/auth/email-verifications")
                .contentType("application/json").content("{\"token\":\"opaque-secret\"}"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.error").value("SERVICE_UNAVAILABLE"))
            .andExpect(jsonPath("$.message").value("Verification is temporarily unavailable"));
    }

    private static final class FakeVerification implements VerifyStaffEmail {
        String token;
        UUID correlationId;
        RuntimeException failure;
        int calls;

        @Override
        public void verify(String token, UUID correlationId) {
            calls++;
            this.token = token;
            this.correlationId = correlationId;
            if (failure != null) throw failure;
        }
    }
}
