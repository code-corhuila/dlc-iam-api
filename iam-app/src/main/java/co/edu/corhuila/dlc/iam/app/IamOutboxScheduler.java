package co.edu.corhuila.dlc.iam.app;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcOutboxDelivery;
import co.edu.corhuila.dlc.iam.application.port.out.OutboxPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Drains a bounded batch; due-time and row claiming remain in the owner repository. */
@Component
public final class IamOutboxScheduler {
    private static final int MAX_EVENTS_PER_TICK = 25;
    private final JdbcOutboxDelivery delivery;
    private final OutboxPublisher publisher;

    public IamOutboxScheduler(JdbcOutboxDelivery delivery, OutboxPublisher publisher) {
        this.delivery = delivery;
        this.publisher = publisher;
    }

    @Scheduled(fixedDelayString = "${iam.outbox.poll-delay-ms:2000}",
               initialDelayString = "${iam.outbox.initial-delay-ms:5000}")
    public void dispatch() {
        for (int i = 0; i < MAX_EVENTS_PER_TICK; i++) {
            if (!delivery.deliverNext(publisher)) return;
        }
    }
}
