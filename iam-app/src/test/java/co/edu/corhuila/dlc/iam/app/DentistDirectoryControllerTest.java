package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.DentistDirectoryController;
import co.edu.corhuila.dlc.iam.application.port.out.DentistDirectory;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.ListDentistsService;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class DentistDirectoryControllerTest {
    private final CurrentActorService actors = mock(CurrentActorService.class);
    private final DentistDirectory directory = mock(DentistDirectory.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(
        new DentistDirectoryController(actors, new ListDentistsService(directory))).build();

    @Test
    void administratorAndSecretaryReadOnlyIdAndName() throws Exception {
        UUID id = UUID.randomUUID();
        when(directory.list(1, 20)).thenReturn(
            new DentistDirectory.Page(List.of(new DentistDirectory.Entry(id, "Ana Ruiz")), 1));
        for (String role : List.of("ADMINISTRATOR", "SECRETARY_ASSISTANT")) {
            authorize(List.of(role));
            mvc.perform(get("/api/v1/auth/dentists").header("Authorization", "Bearer token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].id").value(id.toString()))
                .andExpect(jsonPath("$.data[0].name").value("Ana Ruiz"))
                .andExpect(jsonPath("$.data[0].email").doesNotExist())
                .andExpect(jsonPath("$.data[0].status").doesNotExist())
                .andExpect(jsonPath("$.meta.total").value(1))
                .andExpect(jsonPath("$.meta.totalPages").value(1));
        }
    }

    @Test
    void dentistsAndAnonymousCallersAreRejectedBeforeReading() throws Exception {
        authorize(List.of("DENTIST"));
        mvc.perform(get("/api/v1/auth/dentists").header("Authorization", "Bearer token"))
            .andExpect(status().isForbidden());
        when(actors.authenticate(any())).thenThrow(new InvalidLoginException());
        mvc.perform(get("/api/v1/auth/dentists").header("Authorization", "Bearer bad"))
            .andExpect(status().isUnauthorized());
        verifyNoInteractions(directory);
    }

    @Test
    void invalidPagingIsBadRequestAndAnOutageFailsClosed() throws Exception {
        authorize(List.of("ADMINISTRATOR"));
        mvc.perform(get("/api/v1/auth/dentists?limit=101").header("Authorization", "Bearer token"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
        when(directory.list(1, 20)).thenThrow(new DataAccessResourceFailureException("down"));
        mvc.perform(get("/api/v1/auth/dentists").header("Authorization", "Bearer token"))
            .andExpect(status().isServiceUnavailable());
    }

    private void authorize(List<String> roles) {
        doReturn(new CurrentActorService.Actor(UUID.randomUUID(), UUID.randomUUID(), roles))
            .when(actors).authenticate("Bearer token");
    }
}
