package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.StaffReader;
import java.util.NoSuchElementException;
import java.util.UUID;

public final class ReadStaffService {
    private final StaffReader reader;

    public ReadStaffService(StaffReader reader) {
        this.reader = reader;
    }

    public StaffReader.Staff read(UUID id) {
        if (id == null) throw new IllegalArgumentException("Invalid staff id");
        var staff = reader.find(id);
        if (staff == null) throw new NoSuchElementException("Staff not found");
        return valid(staff);
    }

    public Result list(int page, int limit) {
        if (page < 1 || limit < 1 || limit > 100) {
            throw new IllegalArgumentException("Invalid staff page");
        }
        var result = reader.list(page, limit);
        var data = result.data().stream().map(ReadStaffService::valid).toList();
        long totalPages = result.total() / limit + (result.total() % limit == 0 ? 0 : 1);
        return new Result(data, new Meta(page, limit, result.total(), totalPages));
    }

    private static StaffReader.Staff valid(StaffReader.Staff staff) {
        // Legacy accounts without a name need explicit repair before a contract-valid response.
        if (staff.name() == null || staff.name().isBlank() || staff.version() < 1) {
            throw new IllegalStateException("Staff record needs contract repair");
        }
        return staff;
    }

    public record Result(java.util.List<StaffReader.Staff> data, Meta meta) { }
    public record Meta(int page, int limit, long total, long totalPages) { }
}
