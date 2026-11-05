package co.edu.corhuila.dlc.iam.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface StaffReader {
    Staff find(UUID id);
    Page list(int page, int limit);

    record Staff(UUID id, String email, String name, List<String> roles, String status,
                 Instant createdAt, Instant updatedAt, long version) { }
    record Page(List<Staff> data, long total) { }
}
