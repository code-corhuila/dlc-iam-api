package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.StaffReadController;
import co.edu.corhuila.dlc.iam.application.port.out.StaffReader;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.ReadStaffService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class StaffReadControllerTest {
    private final CurrentActorService actors = mock(CurrentActorService.class);
    private final StaffReader reader = mock(StaffReader.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(
        new StaffReadController(actors, new ReadStaffService(reader))).build();
    private final UUID id = UUID.randomUUID();

    @Test
    void requiresAdministratorBeforeReadingOrCounting() throws Exception {
        when(actors.authenticate(any())).thenThrow(new InvalidLoginException());
        mvc.perform(get("/api/v1/auth/staff").header("Authorization", "Bearer token"))
            .andExpect(status().isUnauthorized());
        authorize(List.of("DENTIST"));
        mvc.perform(get("/api/v1/auth/staff").header("Authorization", "Bearer token"))
            .andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/auth/staff/{id}", id).header("Authorization", "Bearer token"))
            .andExpect(status().isForbidden());
        verifyNoInteractions(reader);
    }

    @Test
    void returnsMinimalStaffAndPageMetadata() throws Exception {
        authorize(List.of("ADMINISTRATOR"));
        var staff = new StaffReader.Staff(id, "ada@example.test", "Ada Staff", List.of("DENTIST"),
            "ACTIVE", Instant.parse("2026-11-01T12:00:00Z"),
            Instant.parse("2026-11-02T12:00:00Z"), 1);
        when(reader.find(id)).thenReturn(staff);
        when(reader.list(2, 1)).thenReturn(new StaffReader.Page(List.of(staff), 3));
        mvc.perform(get("/api/v1/auth/staff/{id}", id).header("Authorization", "Bearer token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.name").value("Ada Staff"))
            .andExpect(jsonPath("$.passwordHash").doesNotExist());
        mvc.perform(get("/api/v1/auth/staff?page=2&limit=1").header("Authorization", "Bearer token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data[0].id").value(id.toString()))
            .andExpect(jsonPath("$.meta.total").value(3))
            .andExpect(jsonPath("$.meta.totalPages").value(3));
    }

    @Test
    void rejectsInvalidPagingAndLegacyIncompleteStaff() throws Exception {
        authorize(List.of("ADMINISTRATOR"));
        mvc.perform(get("/api/v1/auth/staff?page=0").header("Authorization", "Bearer token"))
            .andExpect(status().isBadRequest());
        mvc.perform(get("/api/v1/auth/staff?limit=101").header("Authorization", "Bearer token"))
            .andExpect(status().isBadRequest());
        when(reader.find(id)).thenReturn(new StaffReader.Staff(id, "ada@example.test", null,
            List.of("DENTIST"), "ACTIVE", Instant.now(), Instant.now(), 1));
        mvc.perform(get("/api/v1/auth/staff/{id}", id).header("Authorization", "Bearer token"))
            .andExpect(status().isServiceUnavailable());
    }

    private void authorize(List<String> roles) {
        doReturn(new CurrentActorService.Actor(UUID.randomUUID(), UUID.randomUUID(), roles))
            .when(actors).authenticate("Bearer token");
    }
}
