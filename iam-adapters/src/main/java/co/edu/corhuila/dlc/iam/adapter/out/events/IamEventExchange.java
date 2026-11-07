package co.edu.corhuila.dlc.iam.adapter.out.events;

import org.springframework.amqp.core.TopicExchange;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class IamEventExchange {
    @Bean
    TopicExchange iamOutboxExchange(@Value("${iam.outbox.exchange:iam.events.v1}") String name) {
        return new TopicExchange(name, true, false);
    }
}
