package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.DentistDirectory;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

/** ACTIVE accounts holding DENTIST with a contract-valid name, ordered by name then id. */
@Repository
public class JdbcDentistDirectory implements DentistDirectory {
    private static final String ELIGIBLE = """
        FROM iam.users u
        WHERE u.status = 'ACTIVE' AND u.display_name IS NOT NULL
          AND EXISTS (SELECT 1 FROM iam.user_roles r WHERE r.user_id = u.user_id AND r.role = 'DENTIST')
        """;

    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;

    public JdbcDentistDirectory(JdbcTemplate jdbc, TransactionTemplate transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public Page list(int page, int limit) {
        return transactions.execute(status -> {
            long total = jdbc.queryForObject("SELECT count(*) " + ELIGIBLE, Long.class);
            var data = jdbc.query("SELECT u.user_id, u.display_name " + ELIGIBLE
                    + " ORDER BY u.display_name ASC, u.user_id ASC LIMIT ? OFFSET ?",
                (rs, row) -> new Entry(rs.getObject("user_id", UUID.class), rs.getString("display_name")),
                limit, ((long) page - 1) * limit);
            return new Page(data, total);
        });
    }
}
