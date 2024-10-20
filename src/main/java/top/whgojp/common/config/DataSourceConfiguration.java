//package top.whgojp.common.config;
//
//import com.alibaba.druid.pool.DruidDataSource;
//import org.springframework.boot.context.properties.ConfigurationProperties;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//import javax.activation.DataSource;
//
///**
// * @description <功能描述>
// * @author: whgojp
// * @email: whgojp@foxmail.com
// * @Date: 2024/8/9 13:17
// */
//@Configuration
//public class DataSourceConfiguration {
//
//    @ConfigurationProperties(prefix = "spring.datasource.druid")
//    @Bean
//    public DataSource dataSource(){
//        return (DataSource) new DruidDataSource();
//    }
//}