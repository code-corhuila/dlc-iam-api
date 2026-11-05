package co.edu.corhuila.dlc.iam.adapter.out.persistence;

import co.edu.corhuila.dlc.iam.application.port.out.OutboxPublisher;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

/** Claims one due owner event; a broker failure never undoes its business change. */
@Repository
public final class JdbcOutboxDelivery {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;

    public JdbcOutboxDelivery(JdbcTemplate jdbc, TransactionTemplate transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    /** Returns false when no due event exists. The publisher must confirm before returning. */
    public boolean deliverNext(OutboxPublisher publisher) {
        return Boolean.TRUE.equals(transactions.execute(status -> {
            var rows = jdbc.query("""
                SELECT event_id,event_type,aggregate_id,correlation_id,causation_id,
                       payload::text,occurred_at,delivery_attempts
                  FROM iam.outbox_events
                 WHERE published_at IS NULL AND reconciliation_required_at IS NULL
                   AND next_delivery_at <= statement_timestamp()
                 ORDER BY next_delivery_at,occurred_at,event_id
                 LIMIT 1 FOR UPDATE SKIP LOCKED
                """, (rs, row) -> new Pending(
                    new OutboxPublisher.Event(rs.getObject(1, UUID.class), rs.getString(2),
                        rs.getObject(3, UUID.class), rs.getObject(4, UUID.class),
                        rs.getObject(5, UUID.class), rs.getString(6),
                        rs.getTimestamp(7).toInstant()), rs.getInt(8)));
            if (rows.isEmpty()) return false;
            Pending pending = rows.getFirst();
            try {
                publisher.publish(pending.event());
                jdbc.update("""
                    UPDATE iam.outbox_events SET published_at=statement_timestamp()
                     WHERE event_id=?
                    """, pending.event().id());
            } catch (RuntimeException failure) {
                // Keep only timing and attempt state; neither payload nor broker error is logged.
                int delay = Math.min(300, 1 << Math.min(8, pending.attempts()));
                jdbc.update("""
                    UPDATE iam.outbox_events
                       SET delivery_attempts=delivery_attempts+1,
                           last_delivery_failure_at=statement_timestamp(),
                           next_delivery_at=statement_timestamp() + make_interval(secs => ?),
                           reconciliation_required_at=CASE WHEN delivery_attempts+1=10
                               THEN statement_timestamp() ELSE NULL END
                     WHERE event_id=?
                    """, delay, pending.event().id());
            }
            return true;
        }));
    }

    private record Pending(OutboxPublisher.Event event, int attempts) { }
}
