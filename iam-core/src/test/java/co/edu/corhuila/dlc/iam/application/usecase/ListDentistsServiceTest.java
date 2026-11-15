package co.edu.corhuila.dlc.iam.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.dlc.iam.application.port.out.DentistDirectory;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ListDentistsServiceTest {
    private static final DentistDirectory.Entry ANA =
        new DentistDirectory.Entry(UUID.randomUUID(), "Ana Ruiz");

    @Test
    void returnsTheRequestedPageWithItsMetadata() {
        var service = new ListDentistsService((page, limit) ->
            new DentistDirectory.Page(page == 1 ? List.of(ANA) : List.of(), 3));
        var first = service.list(1, 1);
        assertEquals(List.of(ANA), first.data());
        assertEquals(new ListDentistsService.Meta(1, 1, 3, 3), first.meta());
        assertEquals(List.of(), service.list(4, 1).data());
    }

    @Test
    void rejectsInvalidPagingBeforeReading() {
        var service = new ListDentistsService((page, limit) -> {
            throw new AssertionError("must not read");
        });
        assertThrows(IllegalArgumentException.class, () -> service.list(0, 20));
        assertThrows(IllegalArgumentException.class, () -> service.list(1, 0));
        assertThrows(IllegalArgumentException.class, () -> service.list(1, 101));
    }
}
