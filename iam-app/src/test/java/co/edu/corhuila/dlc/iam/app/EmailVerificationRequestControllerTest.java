package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.EmailVerificationRequestController;
import co.edu.corhuila.dlc.iam.adapter.in.http.TrustedGatewayClientAddress;
import co.edu.corhuila.dlc.iam.application.usecase.RecoveryRateLimitedException;
import co.edu.corhuila.dlc.iam.application.usecase.RequestEmailVerificationService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class EmailVerificationRequestControllerTest {
    private final RequestEmailVerificationService verification = mock(RequestEmailVerificationService.class);
    private final org.springframework.test.web.servlet.MockMvc mvc = MockMvcBuilders
        .standaloneSetup(new EmailVerificationRequestController(verification,
            new TrustedGatewayClientAddress(""))).build();

    @Test
    void usesGatewayStampedClientIpOnlyFromTrustedPeer() throws Exception {
        var trustedMvc = MockMvcBuilders.standaloneSetup(
            new EmailVerificationRequestController(verification,
                new TrustedGatewayClientAddress("172.25.0.10"))).build();
        trustedMvc.perform(post("/api/v1/auth/email-verification-requests")
                .with(request -> { request.setRemoteAddr("172.25.0.10"); return request; })
                .contentType("application/json")
                .header("X-Forwarded-For", "192.0.2.2, 203.0.113.8")
                .content("{\"email\":\"person@example.test\"}"))
            .andExpect(status().isOk());
        verify(verification).request(eq("person@example.test"), eq("203.0.113.8"), any(UUID.class));
    }

    @Test
    void acknowledgesWithoutDisclosingIdentityAndIgnoresForwardedIp() throws Exception {
        mvc.perform(post("/api/v1/auth/email-verification-requests")
                .contentType("application/json")
                .header("X-Forwarded-For", "203.0.113.88")
                .content("{\"email\":\"person@example.test\"}"))
            .andExpect(status().isOk())
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.message").exists())
            .andExpect(jsonPath("$.email").doesNotExist())
            .andExpect(jsonPath("$.token").doesNotExist());
        verify(verification).request(eq("person@example.test"), eq("127.0.0.1"), any(UUID.class));
    }

    @Test
    void invalidBodyDoesNotCallService() throws Exception {
        mvc.perform(post("/api/v1/auth/email-verification-requests")
                .contentType("application/json").content("{\"email\":12}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
        verifyNoInteractions(verification);
    }

    @Test
    void limitAndUnavailableDatabaseHaveGenericResponses() throws Exception {
        doThrow(new RecoveryRateLimitedException()).when(verification)
            .request(any(), any(), any());
        mvc.perform(post("/api/v1/auth/email-verification-requests")
                .contentType("application/json").content("{\"email\":\"person@example.test\"}"))
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.error").value("TOO_MANY_REQUESTS"));
        org.mockito.Mockito.reset(verification);
        doThrow(new DataAccessResourceFailureException("database down")).when(verification)
            .request(any(), any(), any());
        mvc.perform(post("/api/v1/auth/email-verification-requests")
                .contentType("application/json").content("{\"email\":\"person@example.test\"}"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.error").value("SERVICE_UNAVAILABLE"));
    }
}
