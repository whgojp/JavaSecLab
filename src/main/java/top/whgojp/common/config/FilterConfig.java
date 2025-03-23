package top.whgojp.common.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import top.whgojp.modules.mshell.entity.MaliciousFilter;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MaliciousFilter> maliciousFilter() {
        FilterRegistrationBean<MaliciousFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new MaliciousFilter());
        registrationBean.addUrlPatterns("/mshell/filter/*"); // 拦截所有请求
        registrationBean.setOrder(1); // 可以设置过滤器的优先级，值越小，优先级越高
        return registrationBean;
    }
}
