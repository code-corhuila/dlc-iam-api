package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.ServiceClientDirectory;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** Reads a provisioned service client, its secret hashes and grants (iam.service_clients, ADR-020). */
@Repository
public class JdbcServiceClientDirectory implements ServiceClientDirectory {
    private final JdbcTemplate jdbc;

    public JdbcServiceClientDirectory(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<Client> find(String clientId) {
        List<String> status = jdbc.queryForList(
            "SELECT status FROM iam.service_clients WHERE client_id = ?", String.class, clientId);
        if (status.isEmpty()) return Optional.empty();
        List<String> hashes = jdbc.queryForList("SELECT secret_hash FROM iam.service_client_secrets "
            + "WHERE client_id = ? ORDER BY slot", String.class, clientId);
        var grants = new HashSet<>(jdbc.query("SELECT audience, scope FROM iam.service_client_grants "
            + "WHERE client_id = ?", (rs, row) -> new Grant(rs.getString(1), rs.getString(2)), clientId));
        return Optional.of(new Client(clientId, "ACTIVE".equals(status.get(0)), hashes, grants));
    }
}
