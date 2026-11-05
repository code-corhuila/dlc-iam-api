package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.StaffReader;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public final class JdbcStaffReader implements StaffReader {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;

    public JdbcStaffReader(JdbcTemplate jdbc, TransactionTemplate transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public Staff find(UUID id) {
        return transactions.execute(status -> {
            var rows = jdbc.query("""
                SELECT user_id,email,display_name,status,created_at,updated_at,version
                  FROM iam.users WHERE user_id = ?
                """, (rs, row) -> map(rs), id);
            return rows.isEmpty() ? null : rows.getFirst();
        });
    }

    @Override
    public Page list(int page, int limit) {
        return transactions.execute(status -> {
            long total = jdbc.queryForObject("SELECT count(*) FROM iam.users", Long.class);
            long offset = ((long) page - 1) * limit;
            var data = jdbc.query("""
                SELECT user_id,email,display_name,status,created_at,updated_at,version
                  FROM iam.users ORDER BY created_at ASC,user_id ASC LIMIT ? OFFSET ?
                """, (rs, row) -> map(rs), limit, offset);
            return new Page(data, total);
        });
    }

    private Staff map(ResultSet rs) throws SQLException {
        UUID id = rs.getObject("user_id", UUID.class);
        return new Staff(id, rs.getString("email"), rs.getString("display_name"),
            jdbc.queryForList("SELECT role FROM iam.user_roles WHERE user_id = ? ORDER BY role",
                String.class, id), rs.getString("status"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant(), rs.getLong("version"));
    }
}
