package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.UnlockAccountController;
import co.edu.corhuila.dlc.iam.application.port.in.UnlockAccount;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class UnlockAccountControllerTest {
    private final UUID admin = UUID.randomUUID();
    private final UUID staff = UUID.randomUUID();
    private final UUID key = UUID.randomUUID();
    private final CurrentActorService actors = mock(CurrentActorService.class);
    private final UnlockAccount unlocks = mock(UnlockAccount.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(
        new UnlockAccountController(actors, unlocks, new ObjectMapper())).build();

    @Test
    void administratorReceivesApprovedStaffWithoutSecrets() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        when(unlocks.unlock(eq(admin), eq(staff), eq(4L), eq("Reviewed lock"), eq(key), any()))
            .thenReturn(new UnlockAccount.Result(staff, "ada@example.test", "Ada Staff",
                List.of("DENTIST"), "ACTIVE", Instant.parse("2026-11-01T12:00:00Z"),
                Instant.parse("2026-11-04T12:00:00Z"), 5));
        request("{\"reason\":\"Reviewed lock\",\"expectedVersion\":4}", key.toString())
            .andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(jsonPath("$.id").value(staff.toString()))
            .andExpect(jsonPath("$.name").value("Ada Staff"))
            .andExpect(jsonPath("$.roles[0]").value("DENTIST"))
            .andExpect(jsonPath("$.version").value(5))
            .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void malformedPayloadOrIdempotencyKeyDoesNotCallUseCase() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        for (String body : List.of("{}", "{\"reason\":\"x\",\"expectedVersion\":0}",
            "{\"reason\":\" x\",\"expectedVersion\":4}",
            "{\"reason\":\"x\",\"expectedVersion\":4,\"extra\":true}",
            "{\"reason\":\"x\",\"expectedVersion\":4.5}")) {
            request(body, key.toString()).andExpect(status().isBadRequest());
        }
        request("{\"reason\":\"x\",\"expectedVersion\":4}", "bad")
            .andExpect(status().isBadRequest());
        request("{\"reason\":\"x\",\"expectedVersion\":4}", null)
            .andExpect(status().isBadRequest());
        verifyNoInteractions(unlocks);
    }

    @Test
    void requiresAuthenticatedAdministrator() throws Exception {
        when(actors.authenticate(any())).thenThrow(new InvalidLoginException());
        request("{\"reason\":\"Reviewed lock\",\"expectedVersion\":4}", key.toString())
            .andExpect(status().isUnauthorized());
        authenticate(List.of("DENTIST"));
        request("{\"reason\":\"Reviewed lock\",\"expectedVersion\":4}", key.toString())
            .andExpect(status().isForbidden());
        verifyNoInteractions(unlocks);
    }

    @Test
    void mapsConflictAndUnavailableDatabase() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        doThrow(new ConcurrentModificationException()).when(unlocks)
            .unlock(eq(admin), eq(staff), eq(4L), eq("Reviewed lock"), eq(key), any());
        request("{\"reason\":\"Reviewed lock\",\"expectedVersion\":4}", key.toString())
            .andExpect(status().isConflict());
        doThrow(new DataAccessResourceFailureException("db down")).when(unlocks)
            .unlock(eq(admin), eq(staff), eq(4L), eq("Reviewed lock"), eq(key), any());
        request("{\"reason\":\"Reviewed lock\",\"expectedVersion\":4}", key.toString())
            .andExpect(status().isServiceUnavailable());
    }

    private org.springframework.test.web.servlet.ResultActions request(String body, String key)
        throws Exception {
        var builder = post("/api/v1/auth/staff/{id}/unlocks", staff)
            .header("Authorization", "Bearer staff-token")
            .contentType(MediaType.APPLICATION_JSON).content(body);
        if (key != null) builder.header("Idempotency-Key", key);
        return mvc.perform(builder);
    }

    private void authenticate(List<String> roles) {
        doReturn(new CurrentActorService.Actor(admin, UUID.randomUUID(), roles))
            .when(actors).authenticate("Bearer staff-token");
    }
}
