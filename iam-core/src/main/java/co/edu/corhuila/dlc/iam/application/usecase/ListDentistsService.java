package co.edu.corhuila.dlc.iam.application.usecase;

import co.edu.corhuila.dlc.iam.application.port.out.DentistDirectory;
import java.util.List;
import java.util.Objects;

/** Dentist directory for scheduling (dlc-docs#164); page and limit follow the shared pagination rules. */
public final class ListDentistsService {
    private final DentistDirectory directory;

    public ListDentistsService(DentistDirectory directory) {
        this.directory = Objects.requireNonNull(directory, "directory");
    }

    public Result list(int page, int limit) {
        if (page < 1 || limit < 1 || limit > 100) {
            throw new IllegalArgumentException("Invalid dentist page");
        }
        var result = directory.list(page, limit);
        long totalPages = result.total() / limit + (result.total() % limit == 0 ? 0 : 1);
        return new Result(List.copyOf(result.data()), new Meta(page, limit, result.total(), totalPages));
    }

    public record Result(List<DentistDirectory.Entry> data, Meta meta) { }
    public record Meta(int page, int limit, long total, long totalPages) { }
}
