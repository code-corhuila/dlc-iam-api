package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.RoleAssignmentController;
import co.edu.corhuila.dlc.iam.application.port.in.ReplaceRoleAssignments;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class RoleAssignmentControllerTest {
    private final UUID admin = UUID.randomUUID();
    private final UUID staff = UUID.randomUUID();
    private final CurrentActorService actors = mock(CurrentActorService.class);
    private final ReplaceRoleAssignments assignments = mock(ReplaceRoleAssignments.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(
        new RoleAssignmentController(actors, assignments, new ObjectMapper())).build();

    @Test
    void replacesOnlyApprovedRolesAndReturnsMinimizedStaff() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        when(assignments.replace(eq(admin), eq(staff), eq(List.of("DENTIST")), eq(1L),
            eq("Duty change"), any())).thenReturn(new ReplaceRoleAssignments.Staff(
                staff, "ada@example.test", "Ada Staff", List.of("DENTIST"), "ACTIVE", 2));
        request(valid()).andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(jsonPath("$.id").value(staff.toString()))
            .andExpect(jsonPath("$.name").value("Ada Staff"))
            .andExpect(jsonPath("$.roles[0]").value("DENTIST"))
            .andExpect(jsonPath("$.version").value(2))
            .andExpect(jsonPath("$.reason").doesNotExist())
            .andExpect(jsonPath("$.passwordHash").doesNotExist());
        verify(assignments).replace(eq(admin), eq(staff), eq(List.of("DENTIST")),
            eq(1L), eq("Duty change"), any());
    }

    @Test
    void rejectsUnapprovedDuplicateEmptyAndMalformedRolesBeforeUseCase() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        for (String roles : List.of("[]", "[\"DENTIST\",\"DENTIST\"]",
            "[\"ADMINISTRATOR\"]", "[\"PATIENT\"]", "[5]", "\"DENTIST\"")) {
            request("{\"roles\":" + roles
                + ",\"expectedVersion\":1,\"reason\":\"Duty change\"}")
                .andExpect(status().isBadRequest());
        }
        verifyNoInteractions(assignments);
    }

    @Test
    void rejectsUnknownFieldsBadVersionAndReasonBeforeUseCase() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        for (String body : List.of(
            "{\"roles\":[\"DENTIST\"],\"expectedVersion\":1,\"reason\":\"ok\",\"status\":\"ACTIVE\"}",
            "{\"roles\":[\"DENTIST\"],\"expectedVersion\":1.5,\"reason\":\"ok\"}",
            "{\"roles\":[\"DENTIST\"],\"expectedVersion\":0,\"reason\":\"ok\"}",
            "{\"roles\":[\"DENTIST\"],\"expectedVersion\":1,\"reason\":\" \"}",
            "{\"roles\":[\"DENTIST\"],\"expectedVersion\":1,\"reason\":\" padded\"}",
            "{\"roles\":[\"DENTIST\"],\"expectedVersion\":1}")) {
            request(body).andExpect(status().isBadRequest());
        }
        verifyNoInteractions(assignments);
    }

    @Test
    void requiresAuthenticatedAdministrator() throws Exception {
        when(actors.authenticate(any())).thenThrow(new InvalidLoginException());
        request(valid()).andExpect(status().isUnauthorized());
        authenticate(List.of("DENTIST"));
        request(valid()).andExpect(status().isForbidden());
        verifyNoInteractions(assignments);
    }

    @Test
    void mapsOwnerAuthorizationMissingAndVersionConflict() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        doThrow(new SecurityException()).when(assignments).replace(eq(admin), eq(staff),
            eq(List.of("DENTIST")), eq(1L), eq("Duty change"), any());
        request(valid()).andExpect(status().isForbidden());
        doThrow(new NoSuchElementException()).when(assignments).replace(eq(admin), eq(staff),
            eq(List.of("DENTIST")), eq(1L), eq("Duty change"), any());
        request(valid()).andExpect(status().isNotFound());
        doThrow(new ConcurrentModificationException()).when(assignments).replace(eq(admin), eq(staff),
            eq(List.of("DENTIST")), eq(1L), eq("Duty change"), any());
        request(valid()).andExpect(status().isConflict());
    }

    @Test
    void unavailableDatabaseIsRetryableAndGeneric() throws Exception {
        authenticate(List.of("ADMINISTRATOR"));
        doThrow(new DataAccessResourceFailureException("db down")).when(assignments)
            .replace(eq(admin), eq(staff), eq(List.of("DENTIST")), eq(1L),
                eq("Duty change"), any());
        request(valid()).andExpect(status().isServiceUnavailable())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.error").value("SERVICE_UNAVAILABLE"));
    }

    private ResultActions request(String body) throws Exception {
        return mvc.perform(put("/api/v1/auth/staff/{id}/role-assignments", staff)
            .header("Authorization", "Bearer staff-token")
            .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private static String valid() {
        return "{\"roles\":[\"DENTIST\"],\"expectedVersion\":1,\"reason\":\"Duty change\"}";
    }

    private void authenticate(List<String> roles) {
        doReturn(new CurrentActorService.Actor(admin, UUID.randomUUID(), roles))
            .when(actors).authenticate("Bearer staff-token");
    }
}
