package co.edu.corhuila.dlc.iam.app;

import static org.mockito.Mockito.*;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcOutboxDelivery;
import co.edu.corhuila.dlc.iam.application.port.out.OutboxPublisher;
import org.junit.jupiter.api.Test;

class IamOutboxSchedulerTest {
    @Test
    void stopsWhenNoEventIsDue() {
        JdbcOutboxDelivery delivery = mock(JdbcOutboxDelivery.class);
        OutboxPublisher publisher = mock(OutboxPublisher.class);
        when(delivery.deliverNext(publisher)).thenReturn(true, true, false);
        new IamOutboxScheduler(delivery, publisher).dispatch();
        verify(delivery, times(3)).deliverNext(publisher);
    }

    @Test
    void capsEachTickAtTwentyFiveEvents() {
        JdbcOutboxDelivery delivery = mock(JdbcOutboxDelivery.class);
        OutboxPublisher publisher = mock(OutboxPublisher.class);
        when(delivery.deliverNext(publisher)).thenReturn(true);
        new IamOutboxScheduler(delivery, publisher).dispatch();
        verify(delivery, times(25)).deliverNext(publisher);
    }
}
