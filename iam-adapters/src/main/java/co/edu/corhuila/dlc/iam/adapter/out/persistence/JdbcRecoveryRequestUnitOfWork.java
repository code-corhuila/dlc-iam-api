package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.RecoveryRequestUnitOfWork;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

@Repository
public class JdbcRecoveryRequestUnitOfWork implements RecoveryRequestUnitOfWork {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;

    public JdbcRecoveryRequestUnitOfWork(JdbcTemplate jdbc, TransactionTemplate transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public <T> T execute(Function<Store, T> operation) {
        return transactions.execute(status -> operation.apply(new JdbcStore()));
    }

    private final class JdbcStore implements Store {
        @Override
        public UUID verifiedUserForUpdate(String normalizedEmail) {
            var users = jdbc.query("""
                SELECT user_id FROM iam.users
                 WHERE email = ? AND status = 'ACTIVE' AND email_verified_at IS NOT NULL
                 FOR UPDATE
                """, (rs, row) -> rs.getObject(1, UUID.class), normalizedEmail);
            return users.isEmpty() ? null : users.getFirst();
        }

        @Override
        public void createChallenge(UUID challengeId, UUID userId, String purpose,
                                    String tokenHash, Instant createdAt, Instant expiresAt) {
            jdbc.update("""
                UPDATE iam.security_challenges SET consumed_at = statement_timestamp()
                 WHERE user_id = ? AND purpose = ? AND consumed_at IS NULL
                   AND created_at <= statement_timestamp()
                   AND expires_at > statement_timestamp()
                """, userId, purpose);
            jdbc.update("""
                INSERT INTO iam.security_challenges
                  (challenge_id,user_id,purpose,token_hash,created_at,expires_at)
                VALUES (?,?,?,?,?,?)
                """, challengeId, userId, purpose, tokenHash,
                Timestamp.from(createdAt), Timestamp.from(expiresAt));
        }
    }
}
