package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.StaffNameController;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.UpdateStaffNameService;
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

class StaffNameControllerTest {
    private final UUID admin = UUID.randomUUID();
    private final UUID staff = UUID.randomUUID();
    private final CurrentActorService actors = mock(CurrentActorService.class);
    private final UpdateStaffNameService names = mock(UpdateStaffNameService.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(
        new StaffNameController(actors, names, new ObjectMapper())).build();

    @Test
    void returnsApprovedStaffShapeWithoutCredentials() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        when(names.update(eq(admin), eq(staff), eq("Ada Staff"), eq(1L), any()))
            .thenReturn(new UpdateStaffNameService.Result(staff, "ada@example.test", "Ada Staff",
                List.of("DENTIST"), "ACTIVE", Instant.parse("2026-11-01T12:00:00Z"),
                Instant.parse("2026-11-04T12:00:00Z"), 2));
        mvc.perform(patch("/api/v1/auth/staff/{id}", staff)
                .header("Authorization", "Bearer staff-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Ada Staff\",\"expectedVersion\":1}"))
            .andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(jsonPath("$.id").value(staff.toString()))
            .andExpect(jsonPath("$.name").value("Ada Staff"))
            .andExpect(jsonPath("$.roles[0]").value("DENTIST"))
            .andExpect(jsonPath("$.version").value(2))
            .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void rejectsUnknownFieldsAndInvalidVersion() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        for (String body : List.of("{\"name\":\"Ada\",\"expectedVersion\":1,\"role\":\"ADMINISTRATOR\"}",
            "{\"name\":\"Ada\",\"expectedVersion\":1.5}",
            "{\"name\":\"Ada\"}", "{\"name\":null,\"expectedVersion\":1}")) {
            mvc.perform(patch("/api/v1/auth/staff/{id}", staff)
                    .header("Authorization", "Bearer staff-token")
                    .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
        }
        verifyNoInteractions(names);
    }

    @Test
    void requiresAuthenticatedAdministratorBeforeUpdate() throws Exception {
        when(actors.authenticate(any())).thenThrow(new InvalidLoginException());
        request().andExpect(status().isUnauthorized());
        authenticate(List.of("DENTIST"));
        request().andExpect(status().isForbidden());
        verifyNoInteractions(names);
    }

    @Test
    void mapsVersionConflictAndDatabaseOutage() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        doThrow(new ConcurrentModificationException()).when(names)
            .update(eq(admin), eq(staff), eq("Ada Staff"), eq(1L), any());
        request().andExpect(status().isConflict());
        doThrow(new DataAccessResourceFailureException("db down")).when(names)
            .update(eq(admin), eq(staff), eq("Ada Staff"), eq(1L), any());
        request().andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.error").value("SERVICE_UNAVAILABLE"));
    }

    private org.springframework.test.web.servlet.ResultActions request() throws Exception {
        return mvc.perform(patch("/api/v1/auth/staff/{id}", staff)
            .header("Authorization", "Bearer staff-token")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"name\":\"Ada Staff\",\"expectedVersion\":1}"));
    }

    private void authenticate(List<String> roles) {
        doReturn(new CurrentActorService.Actor(admin, UUID.randomUUID(), roles))
            .when(actors).authenticate("Bearer staff-token");
    }
}
