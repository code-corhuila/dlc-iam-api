package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.OwnSessionListController;
import co.edu.corhuila.dlc.iam.application.port.out.OwnSessionReader;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.ListOwnSessionsService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class OwnSessionListControllerTest {
    private static final UUID OWNER = UUID.randomUUID();
    private static final UUID CURRENT = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-11-02T10:00:00Z");
    private final CurrentActorService actors = mock(CurrentActorService.class);
    private final OwnSessionReader reader = mock(OwnSessionReader.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new OwnSessionListController(
        actors, new ListOwnSessionsService(reader))).build();

    @Test
    void listsOnlyActorSessionsWithContractPageAndNoNullDevice() throws Exception {
        authenticate(List.of("DENTIST"));
        when(reader.read(OWNER, 2, 2)).thenReturn(new OwnSessionReader.Page(3, List.of(
            new OwnSessionReader.Session(CURRENT, null, NOW, NOW, NOW.plusSeconds(60), 2))));
        mvc.perform(get("/api/v1/auth/sessions?page=2&limit=2")
                .header("Authorization", "Bearer staff-token"))
            .andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(jsonPath("$.data[0].id").value(CURRENT.toString()))
            .andExpect(jsonPath("$.data[0].current").value(true))
            .andExpect(jsonPath("$.data[0].version").value(2))
            .andExpect(jsonPath("$.data[0].device").doesNotExist())
            .andExpect(jsonPath("$.meta.total").value(3))
            .andExpect(jsonPath("$.meta.totalPages").value(2));
        verify(reader).read(OWNER, 2, 2);
    }

    @Test
    void rejectsInvalidPagesAfterAuthentication() throws Exception {
        authenticate(List.of("SECRETARY_ASSISTANT"));
        for (String query : List.of("page=0", "page=abc", "limit=101", "limit=-1")) {
            mvc.perform(get("/api/v1/auth/sessions?" + query)
                    .header("Authorization", "Bearer staff-token"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
        }
        verifyNoInteractions(reader);
    }

    @Test
    void requiresActiveStaffActorBeforeAnyRead() throws Exception {
        when(actors.authenticate(any())).thenThrow(new InvalidLoginException());
        mvc.perform(get("/api/v1/auth/sessions?page=bad")
                .header("Authorization", "Bearer staff-token"))
            .andExpect(status().isUnauthorized());
        authenticate(List.of("PATIENT"));
        mvc.perform(get("/api/v1/auth/sessions")
                .header("Authorization", "Bearer staff-token"))
            .andExpect(status().isForbidden());
        verifyNoInteractions(reader);
    }

    @Test
    void unavailableDatabaseReturnsGenericRetryableResponse() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        doThrow(new DataAccessResourceFailureException("db down"))
            .when(reader).read(OWNER, 20, 0);
        mvc.perform(get("/api/v1/auth/sessions")
                .header("Authorization", "Bearer staff-token"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.error").value("SERVICE_UNAVAILABLE"))
            .andExpect(jsonPath("$.message").value("Session listing is temporarily unavailable"));
    }

    private void authenticate(List<String> roles) {
        doReturn(new CurrentActorService.Actor(OWNER, CURRENT, roles))
            .when(actors).authenticate("Bearer staff-token");
    }
}
