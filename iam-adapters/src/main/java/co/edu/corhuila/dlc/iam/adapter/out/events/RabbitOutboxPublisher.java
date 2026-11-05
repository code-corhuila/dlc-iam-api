package co.edu.corhuila.dlc.iam.adapter.out.events;

import co.edu.corhuila.dlc.iam.application.port.out.OutboxPublisher;
import java.util.concurrent.TimeUnit;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageDeliveryMode;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Confirms a persistent routed message before the JDBC outbox marks it published. */
@Component
public final class RabbitOutboxPublisher implements OutboxPublisher {
    private final RabbitTemplate rabbit;
    private final IamEventEnvelope envelope;
    private final String exchange;

    public RabbitOutboxPublisher(RabbitTemplate rabbit, IamEventEnvelope envelope,
                                 @Value("${iam.outbox.exchange:iam.events.v1}") String exchange) {
        this.rabbit = rabbit;
        this.envelope = envelope;
        this.exchange = exchange;
    }

    @Override
    public void publish(Event event) {
        MessageProperties properties = new MessageProperties();
        properties.setContentType(MessageProperties.CONTENT_TYPE_JSON);
        properties.setDeliveryMode(MessageDeliveryMode.PERSISTENT);
        properties.setMessageId(event.id().toString());
        Message message = new Message(envelope.serialize(event), properties);
        CorrelationData confirmation = new CorrelationData(event.id().toString());
        rabbit.send(exchange, "iam." + event.type() + ".v1", message, confirmation);
        try {
            var result = confirmation.getFuture().get(5, TimeUnit.SECONDS);
            if (!result.isAck() || confirmation.getReturned() != null) {
                throw new IllegalStateException("IAM event was not durably routed");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("IAM event confirmation interrupted", interrupted);
        } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException failure) {
            throw new IllegalStateException("IAM event confirmation unavailable", failure);
        }
    }
}
