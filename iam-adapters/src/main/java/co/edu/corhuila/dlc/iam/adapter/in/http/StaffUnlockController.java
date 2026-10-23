package co.edu.corhuila.dlc.iam.adapter.in.http;

import co.edu.corhuila.dlc.iam.application.port.in.LoginUseCase;
import co.edu.corhuila.dlc.iam.application.usecase.CurrentActorService;
import co.edu.corhuila.dlc.iam.application.usecase.UnlockStaffService;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/staff")
public class StaffUnlockController {
    private final CurrentActorService actors;
    private final UnlockStaffService unlocks;

    public StaffUnlockController(CurrentActorService actors, UnlockStaffService unlocks) {
        this.actors = actors;
        this.unlocks = unlocks;
    }

    @PostMapping("/{id}/unlocks")
    public ResponseEntity<LoginUseCase.Staff> unlock(@PathVariable UUID id,
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
        String authorization) {
        var actor = actors.authenticate(authorization);
        UUID correlationId = UUID.randomUUID();
        var staff = unlocks.unlock(actor.userId(), actor.sessionId(), id, correlationId);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
            .header("X-Correlation-Id", correlationId.toString()).body(staff);
    }
}
