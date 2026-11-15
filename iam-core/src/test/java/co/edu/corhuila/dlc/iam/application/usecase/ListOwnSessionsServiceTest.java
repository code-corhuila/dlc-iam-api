package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.OwnSessionReader;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ListOwnSessionsServiceTest {
    private static final UUID OWNER = UUID.randomUUID();
    private static final UUID CURRENT = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-11-02T10:00:00Z");

    @Test
    void marksOnlyCurrentSessionAndCalculatesMetadata() {
        var other = UUID.randomUUID();
        OwnSessionReader reader = (owner, limit, offset) -> {
            assertEquals(OWNER, owner);
            assertEquals(2, limit);
            assertEquals(2, offset);
            return new OwnSessionReader.Page(5, List.of(
                new OwnSessionReader.Session(other, null, NOW, NOW, NOW.plusSeconds(60), 3),
                new OwnSessionReader.Session(CURRENT, "browser", NOW, NOW, NOW.plusSeconds(60), 4)));
        };
        var page = new ListOwnSessionsService(reader).list(OWNER, CURRENT, 2, 2);
        assertEquals(5, page.meta().total());
        assertEquals(3, page.meta().totalPages());
        assertEquals(false, page.data().get(0).current());
        assertEquals(true, page.data().get(1).current());
        assertEquals(4, page.data().get(1).version());
    }

    @Test
    void rejectsInvalidPageBeforeReading() {
        OwnSessionReader reader = (owner, limit, offset) -> {
            throw new AssertionError("reader must not be invoked");
        };
        var service = new ListOwnSessionsService(reader);
        assertThrows(IllegalArgumentException.class, () -> service.list(OWNER, CURRENT, 0, 20));
        assertThrows(IllegalArgumentException.class, () -> service.list(OWNER, CURRENT, 1, 101));
        assertThrows(IllegalArgumentException.class, () -> service.list(null, CURRENT, 1, 20));
        var empty = new ListOwnSessionsService((owner, limit, offset) ->
            new OwnSessionReader.Page(0, List.of())).list(OWNER, CURRENT, 99, 20);
        assertEquals(0, empty.meta().totalPages());
        assertEquals(List.of(), empty.data());
    }
}
