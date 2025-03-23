package top.whgojp.modules.sqli.config;

import com.alibaba.druid.pool.DruidDataSource;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class DynamicDataSourceConfig {

    @Bean
    @Primary
    @ConfigurationProperties("spring.datasource.primary")
    public DataSourceProperties dataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean
    @Primary
    public DataSource dataSource(DataSourceProperties dataSourceProperties) {
        AbstractRoutingDataSource dataSource = new AbstractRoutingDataSource() {
            @Override
            protected Object determineCurrentLookupKey() {
                return DynamicDataSourceContextHolder.getDataSourceType();
            }
        };

        DruidDataSource primaryDataSource = new DruidDataSource();
        primaryDataSource.setUrl(dataSourceProperties.getUrl());
        primaryDataSource.setUsername(dataSourceProperties.getUsername());
        primaryDataSource.setPassword(dataSourceProperties.getPassword());
        primaryDataSource.setDriverClassName(dataSourceProperties.getDriverClassName());
        primaryDataSource.setInitialSize(5);
        primaryDataSource.setMinIdle(5);
        primaryDataSource.setMaxActive(20);
        primaryDataSource.setMaxWait(30000);
        primaryDataSource.setValidationQuery("SELECT 1 FROM DUAL");
        primaryDataSource.setTestWhileIdle(true);
        primaryDataSource.setTimeBetweenEvictionRunsMillis(60000);
        primaryDataSource.setMinEvictableIdleTimeMillis(300000);
        primaryDataSource.setPoolPreparedStatements(true);
        primaryDataSource.setMaxPoolPreparedStatementPerConnectionSize(20);
        primaryDataSource.setLogAbandoned(true);
        primaryDataSource.setRemoveAbandoned(true);
        primaryDataSource.setRemoveAbandonedTimeout(180);

        DruidDataSource secondaryDataSource = new DruidDataSource();
        secondaryDataSource.setUrl(dataSourceProperties.getUrl());
        secondaryDataSource.setUsername(dataSourceProperties.getUsername());
        secondaryDataSource.setPassword(dataSourceProperties.getPassword());
        secondaryDataSource.setDriverClassName(dataSourceProperties.getDriverClassName());
        secondaryDataSource.setInitialSize(5);
        secondaryDataSource.setMinIdle(5);
        secondaryDataSource.setMaxActive(20);
        secondaryDataSource.setMaxWait(30000);
        secondaryDataSource.setValidationQuery("SELECT 1 FROM DUAL");
        secondaryDataSource.setTestWhileIdle(true);
        secondaryDataSource.setTimeBetweenEvictionRunsMillis(60000);
        secondaryDataSource.setMinEvictableIdleTimeMillis(300000);
        secondaryDataSource.setPoolPreparedStatements(true);
        secondaryDataSource.setMaxPoolPreparedStatementPerConnectionSize(20);
        secondaryDataSource.setLogAbandoned(true);
        secondaryDataSource.setRemoveAbandoned(true);
        secondaryDataSource.setRemoveAbandonedTimeout(180);

        Map<Object, Object> targetDataSources = new HashMap<>();
        targetDataSources.put("primary", primaryDataSource);
        targetDataSources.put("secondary", secondaryDataSource);

        dataSource.setTargetDataSources(targetDataSources);
        dataSource.setDefaultTargetDataSource(primaryDataSource);

        return dataSource;
    }

    @Bean
    @Primary
    public LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource dataSource) {
        LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
        em.setDataSource(dataSource);
        em.setPackagesToScan("top.whgojp.modules.sqli.entity");
        
        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        em.setJpaVendorAdapter(vendorAdapter);
        
        Map<String, Object> properties = new HashMap<>();
        properties.put("hibernate.hbm2ddl.auto", "update");
        properties.put("hibernate.dialect", "org.hibernate.dialect.MySQL8Dialect");
        em.setJpaPropertyMap(properties);
        
        return em;
    }

    @Bean(name = "jpaTransactionManager")
    @Primary
    public JpaTransactionManager jpaTransactionManager(EntityManagerFactory emf) {
        JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setEntityManagerFactory(emf);
        return transactionManager;
    }
} 