package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcLoginAttemptLimiter;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

class JdbcLoginAttemptLimiterTest {
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final TransactionTemplate transactions = mock(TransactionTemplate.class);

    @Test
    void shortDigestKeyIsRejectedAtStartup() {
        assertThrows(IllegalArgumentException.class,
            () -> new JdbcLoginAttemptLimiter(jdbc, transactions,
                Base64.getEncoder().encodeToString(new byte[8])));
    }

    @Test
    void nonNumericPeerIsRejectedBeforeDatabaseAccess() {
        var limiter = new JdbcLoginAttemptLimiter(jdbc, transactions,
            Base64.getEncoder().encodeToString(new byte[32]));
        assertThrows(IllegalArgumentException.class,
            () -> limiter.record("attacker.example.test"));
        verifyNoInteractions(jdbc, transactions);
    }
}
