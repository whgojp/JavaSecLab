package top.whgojp.common.config;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.transaction.ChainedTransactionManager;
import org.springframework.orm.hibernate5.HibernateTransactionManager;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.persistence.EntityManagerFactory;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/10/1 16:51
 */
@Configuration
@EnableTransactionManagement
public class TransactionConfig {

    @Bean
    public PlatformTransactionManager transactionManager(
            @Qualifier("jpaTransactionManager") JpaTransactionManager jpaTransactionManager,
            @Qualifier("hibernateTransactionManager") HibernateTransactionManager hibernateTransactionManager) {

        return new ChainedTransactionManager(jpaTransactionManager, hibernateTransactionManager);
    }

    @Bean(name = "jpaTransactionManager")
    public JpaTransactionManager jpaTransactionManager(EntityManagerFactory entityManagerFactory) {
        return new JpaTransactionManager(entityManagerFactory);
    }

    @Bean(name = "hibernateTransactionManager")
    public HibernateTransactionManager hibernateTransactionManager(SessionFactory sessionFactory) {
        return new HibernateTransactionManager(sessionFactory);
    }
}
