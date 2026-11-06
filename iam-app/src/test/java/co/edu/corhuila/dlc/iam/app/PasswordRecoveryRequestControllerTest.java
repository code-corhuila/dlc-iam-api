package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.PasswordRecoveryRequestController;
import co.edu.corhuila.dlc.iam.adapter.in.http.TrustedGatewayClientAddress;
import co.edu.corhuila.dlc.iam.application.usecase.RecoveryRateLimitedException;
import co.edu.corhuila.dlc.iam.application.usecase.RequestPasswordRecoveryService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class PasswordRecoveryRequestControllerTest {
    private final RequestPasswordRecoveryService recovery = mock(RequestPasswordRecoveryService.class);
    private final org.springframework.test.web.servlet.MockMvc mvc = MockMvcBuilders
        .standaloneSetup(new PasswordRecoveryRequestController(recovery,
            new TrustedGatewayClientAddress(""))).build();

    @Test
    void usesGatewayStampedClientIpOnlyFromTrustedPeer() throws Exception {
        var trustedMvc = MockMvcBuilders.standaloneSetup(
            new PasswordRecoveryRequestController(recovery,
                new TrustedGatewayClientAddress("172.25.0.10"))).build();
        trustedMvc.perform(post("/api/v1/auth/password-recovery-requests")
                .with(request -> { request.setRemoteAddr("172.25.0.10"); return request; })
                .contentType("application/json")
                .header("X-Forwarded-For", "192.0.2.2, 198.51.100.9")
                .content("{\"email\":\"person@example.test\"}"))
            .andExpect(status().isOk());
        verify(recovery).request(eq("person@example.test"), eq("198.51.100.9"), any(UUID.class));
    }

    @Test
    void acknowledgesWithoutReturningIdentityAndUsesConnectionPeer() throws Exception {
        mvc.perform(post("/api/v1/auth/password-recovery-requests")
                .contentType("application/json")
                .header("X-Forwarded-For", "203.0.113.88")
                .content("{\"email\":\"person@example.test\"}"))
            .andExpect(status().isOk())
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.message").exists())
            .andExpect(jsonPath("$.email").doesNotExist())
            .andExpect(jsonPath("$.token").doesNotExist());
        verify(recovery).request(eq("person@example.test"), eq("127.0.0.1"), any(UUID.class));
    }

    @Test
    void rejectsInvalidBodyBeforeUseCase() throws Exception {
        mvc.perform(post("/api/v1/auth/password-recovery-requests")
                .contentType("application/json").content("{\"email\":23}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
        verifyNoInteractions(recovery);
    }

    @Test
    void rateLimitAndUnavailableDatabaseDoNotExposeIdentifiers() throws Exception {
        doThrow(new RecoveryRateLimitedException()).when(recovery)
            .request(any(), any(), any());
        mvc.perform(post("/api/v1/auth/password-recovery-requests")
                .contentType("application/json").content("{\"email\":\"person@example.test\"}"))
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.error").value("TOO_MANY_REQUESTS"));
        org.mockito.Mockito.reset(recovery);
        doThrow(new DataAccessResourceFailureException("database down")).when(recovery)
            .request(any(), any(), any());
        mvc.perform(post("/api/v1/auth/password-recovery-requests")
                .contentType("application/json").content("{\"email\":\"person@example.test\"}"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.error").value("SERVICE_UNAVAILABLE"))
            .andExpect(jsonPath("$.message").value("Recovery is temporarily unavailable"));
    }
}
