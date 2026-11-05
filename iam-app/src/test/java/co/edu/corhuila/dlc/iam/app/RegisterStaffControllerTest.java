package co.edu.corhuila.dlc.iam.app;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.dlc.iam.adapter.in.http.RegisterStaffController;
import co.edu.corhuila.dlc.iam.application.port.out.RegistrationUnitOfWork;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.InvalidLoginException;
import co.edu.corhuila.dlc.iam.application.usecase.RegisterStaffService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class RegisterStaffControllerTest {
    private final UUID admin = UUID.randomUUID();
    private final UUID key = UUID.randomUUID();
    private final UUID staffId = UUID.randomUUID();
    private final CurrentActorService actors = mock(CurrentActorService.class);
    private final RegisterStaffService registrations = mock(RegisterStaffService.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(
        new RegisterStaffController(actors, registrations, new ObjectMapper())).build();

    @Test
    void createsPendingStaffWithLocationAndNoCredentialFields() throws Exception {
        authorize(List.of("ADMINISTRATOR"));
        when(registrations.register(eq(admin), eq("ada@example.test"), eq("Password1"),
            eq("Ada Staff"), eq("DENTIST"), eq(key), any())).thenReturn(
                new RegistrationUnitOfWork.Staff(staffId, "ada@example.test", "Ada Staff",
                    "DENTIST", "PENDING_VERIFICATION", Instant.parse("2026-11-05T10:00:00Z"), 1));
        request("{\"email\":\"ada@example.test\",\"password\":\"Password1\","
            + "\"name\":\"Ada Staff\",\"role\":\"DENTIST\"}")
            .andExpect(status().isCreated())
            .andExpect(header().string("Location", "/api/v1/auth/staff/" + staffId))
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.id").value(staffId.toString()))
            .andExpect(jsonPath("$.roles[0]").value("DENTIST"))
            .andExpect(jsonPath("$.status").value("PENDING_VERIFICATION"))
            .andExpect(jsonPath("$.password").doesNotExist())
            .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void authorizesBeforeParsingOrWriting() throws Exception {
        when(actors.authenticate(any())).thenThrow(new InvalidLoginException());
        request("{}").andExpect(status().isUnauthorized());
        authorize(List.of("DENTIST"));
        request("{}").andExpect(status().isForbidden());
        verifyNoInteractions(registrations);
    }

    @Test
    void rejectsUnknownFieldsMissingKeyAndInvalidRole() throws Exception {
        authorize(List.of("ADMINISTRATOR"));
        request("{\"email\":\"ada@example.test\",\"password\":\"Password1\","
            + "\"name\":\"Ada Staff\",\"role\":\"DENTIST\",\"admin\":true}")
            .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/auth/register").header("Authorization", "Bearer staff-token")
            .contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isBadRequest());
        when(registrations.register(eq(admin), eq("ada@example.test"), eq("Password1"),
            eq("Ada Staff"), eq("ADMINISTRATOR"), eq(key), any()))
            .thenThrow(new IllegalArgumentException("Invalid staff registration"));
        request("{\"email\":\"ada@example.test\",\"password\":\"Password1\","
            + "\"name\":\"Ada Staff\",\"role\":\"ADMINISTRATOR\"}")
            .andExpect(status().isBadRequest());
    }

    private org.springframework.test.web.servlet.ResultActions request(String body) throws Exception {
        return mvc.perform(post("/api/v1/auth/register")
            .header("Authorization", "Bearer staff-token")
            .header("Idempotency-Key", key.toString())
            .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private void authorize(List<String> roles) {
        doReturn(new CurrentActorService.Actor(admin, UUID.randomUUID(), roles))
            .when(actors).authenticate("Bearer staff-token");
    }
}
