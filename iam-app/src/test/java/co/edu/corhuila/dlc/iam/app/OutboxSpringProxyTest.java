package co.edu.corhuila.dlc.iam.app;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import co.edu.corhuila.dlc.iam.adapter.out.persistence.JdbcOutboxDelivery;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.dao.annotation.PersistenceExceptionTranslationPostProcessor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

class OutboxSpringProxyTest {
    @Test
    void repositoryCanBeProxiedDuringContextStartup() {
        try (var context = new AnnotationConfigApplicationContext()) {
            context.registerBean(PersistenceExceptionTranslationPostProcessor.class);
            context.registerBean(JdbcOutboxDelivery.class,
                () -> new JdbcOutboxDelivery(new JdbcTemplate(), new TransactionTemplate()));
            context.refresh();
            assertNotNull(context.getBean(JdbcOutboxDelivery.class));
        }
    }
}
