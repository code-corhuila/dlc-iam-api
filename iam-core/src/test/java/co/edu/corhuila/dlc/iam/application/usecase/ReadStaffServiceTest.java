package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.StaffReader;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ReadStaffServiceTest {
    private static final UUID ID = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void readsMinimalStaffAndPaginatesEmptyBeyondLastPage() {
        var service = new ReadStaffService(new Stub(staff("Ana", 1)));
        assertEquals("Ana", service.read(ID).name());
        var first = service.list(1, 20);
        assertEquals(1, first.data().size());
        assertEquals(1, first.meta().totalPages());
        assertEquals(0, service.list(2, 20).data().size());
        assertEquals(1, service.list(2, 20).meta().total());
    }

    @Test
    void rejectsInvalidPageMissingStaffAndLegacyIncompleteName() {
        var service = new ReadStaffService(new Stub(staff(null, 1)));
        assertThrows(IllegalArgumentException.class, () -> service.list(0, 20));
        assertThrows(IllegalArgumentException.class, () -> service.list(1, 101));
        assertThrows(NoSuchElementException.class, () -> service.read(UUID.randomUUID()));
        assertThrows(IllegalStateException.class, () -> service.read(ID));
        assertThrows(IllegalStateException.class, () -> service.list(1, 20));
    }

    private static StaffReader.Staff staff(String name, long version) {
        return new StaffReader.Staff(ID, "ana@example.org", name, List.of("DENTIST"),
            "ACTIVE", NOW, NOW, version);
    }

    private record Stub(StaffReader.Staff staff) implements StaffReader {
        @Override public Staff find(UUID id) { return ID.equals(id) ? staff : null; }
        @Override public Page list(int page, int limit) {
            return new Page(page == 1 ? List.of(staff) : List.of(), 1);
        }
    }
}
