package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.LoginErrors;
import co.edu.corhuila.dlc.iam.adapter.in.http.StaffUnlockController;
import co.edu.corhuila.dlc.iam.application.port.in.LoginUseCase;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.UnlockStaffService;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class StaffUnlockControllerTest {
    private final CurrentActorService actors = mock(CurrentActorService.class);
    private final UnlockStaffService unlocks = mock(UnlockStaffService.class);
    private final UUID target = UUID.randomUUID();
    private final UUID actor = UUID.randomUUID();
    private final UUID session = UUID.randomUUID();

    @Test
    void returnsMinimizedStaffAfterAuthorizedUnlock() throws Exception {
        when(actors.authenticate("Bearer valid"))
            .thenReturn(new CurrentActorService.Actor(actor, session,
                List.of("ADMINISTRATOR")));
        when(unlocks.unlock(any(UUID.class), any(UUID.class), any(UUID.class),
            any(UUID.class))).thenReturn(new LoginUseCase.Staff(target,
                "staff@example.test", "Staff", List.of("DENTIST"), "ACTIVE", 4));
        mvc().perform(post(path()).header("Authorization", "Bearer valid"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("ACTIVE"))
            .andExpect(jsonPath("$.passwordHash").doesNotExist())
            .andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    void reportsMissingCredentialsAndForbiddenActor() throws Exception {
        when(actors.authenticate((String) null)).thenThrow(new InvalidLoginException());
        when(actors.authenticate("Bearer valid"))
            .thenReturn(new CurrentActorService.Actor(actor, session, List.of("DENTIST")));
        when(unlocks.unlock(any(UUID.class), any(UUID.class), any(UUID.class),
            any(UUID.class))).thenThrow(new UnlockStaffService.Forbidden());
        mvc().perform(post(path())).andExpect(status().isUnauthorized());
        mvc().perform(post(path()).header("Authorization", "Bearer valid"))
            .andExpect(status().isForbidden());
    }

    private String path() {
        return "/api/v1/auth/staff/" + target + "/unlocks";
    }

    private org.springframework.test.web.servlet.MockMvc mvc() {
        return MockMvcBuilders.standaloneSetup(new StaffUnlockController(actors, unlocks))
            .setControllerAdvice(new LoginErrors()).build();
    }
}
