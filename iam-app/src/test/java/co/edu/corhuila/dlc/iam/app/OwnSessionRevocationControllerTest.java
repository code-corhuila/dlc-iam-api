package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.OwnSessionRevocationController;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.RevokeOwnSessionService;
import co.edu.corhuila.dlc.iam.application.usecase.SessionRevocationConflictException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class OwnSessionRevocationControllerTest {
    private static final UUID OWNER = UUID.randomUUID();
    private static final UUID SESSION = UUID.randomUUID();
    private static final UUID KEY = UUID.randomUUID();
    private final CurrentActorService actors = mock(CurrentActorService.class);
    private final RevokeOwnSessionService revocations = mock(RevokeOwnSessionService.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(
        new OwnSessionRevocationController(actors, revocations, new ObjectMapper())).build();

    @BeforeEach
    void authenticatedDentist() {
        when(actors.authenticate("Bearer staff-token")).thenReturn(
            new CurrentActorService.Actor(OWNER, SESSION, List.of("DENTIST")));
    }

    @Test
    void revokesOwnSessionWithNoBodyAndCorrelation() throws Exception {
        request(SESSION.toString(), KEY.toString(), "{\"reason\":\"User request\"}")
            .andExpect(status().isNoContent())
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(header().string("Cache-Control", "no-store"));
        verify(revocations).revoke(eq(OWNER), eq(SESSION), eq(KEY),
            eq("User request"), any(UUID.class));
    }

    @Test
    void rejectsMissingKeyInvalidBodyAndUnexpectedFields() throws Exception {
        request(SESSION.toString(), null, "{\"reason\":\"User request\"}")
            .andExpect(status().isBadRequest());
        request(SESSION.toString(), "bad-key", "{\"reason\":\"User request\"}")
            .andExpect(status().isBadRequest());
        request(SESSION.toString(), KEY.toString(), "{\"reason\":\"\"}")
            .andExpect(status().isBadRequest());
        request(SESSION.toString(), KEY.toString(), "{")
            .andExpect(status().isBadRequest());
        request(SESSION.toString(), KEY.toString(),
            "{\"reason\":\"User request\",\"userId\":\"other\"}")
            .andExpect(status().isBadRequest());
        verifyNoInteractions(revocations);
    }

    @Test
    void authenticationAndRolesAreEnforcedBeforeRequestProcessing() throws Exception {
        doThrow(new InvalidLoginException()).when(actors).authenticate("Bearer staff-token");
        request(SESSION.toString(), KEY.toString(), "{\"reason\":\"User request\"}")
            .andExpect(status().isUnauthorized());
        request(SESSION.toString(), KEY.toString(), "{")
            .andExpect(status().isUnauthorized());
        doReturn(new CurrentActorService.Actor(OWNER, SESSION, List.of("PATIENT")))
            .when(actors).authenticate("Bearer staff-token");
        request(SESSION.toString(), KEY.toString(), "{\"reason\":\"User request\"}")
            .andExpect(status().isForbidden());
        verifyNoInteractions(revocations);
    }

    @Test
    void foreignSessionIsIndistinguishableFromMissingSession() throws Exception {
        doThrow(new NoSuchElementException("foreign owner"))
            .when(revocations).revoke(eq(OWNER), eq(SESSION), eq(KEY), any(), any());
        request(SESSION.toString(), KEY.toString(), "{\"reason\":\"User request\"}")
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.message").value("Session not found"));
    }

    @Test
    void changedReplayReturnsSpecifiedIdempotencyConflict() throws Exception {
        doThrow(new SessionRevocationConflictException("IDEMPOTENCY_CONFLICT", "changed"))
            .when(revocations).revoke(eq(OWNER), eq(SESSION), eq(KEY), any(), any());
        request(SESSION.toString(), KEY.toString(), "{\"reason\":\"User request\"}")
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.error").value("IDEMPOTENCY_CONFLICT"));
    }

    @Test
    void unavailableDatabaseReturnsServiceUnavailable() throws Exception {
        doThrow(new DataAccessResourceFailureException("db down"))
            .when(revocations).revoke(eq(OWNER), eq(SESSION), eq(KEY), any(), any());
        request(SESSION.toString(), KEY.toString(), "{\"reason\":\"User request\"}")
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.error").value("SERVICE_UNAVAILABLE"));
    }

    private org.springframework.test.web.servlet.ResultActions request(String id, String key,
                                                                        String body) throws Exception {
        var request = post("/api/v1/auth/sessions/{id}/revocations", id)
            .header("Authorization", "Bearer staff-token").contentType("application/json")
            .content(body);
        if (key != null) request.header("Idempotency-Key", key);
        return mvc.perform(request);
    }
}
