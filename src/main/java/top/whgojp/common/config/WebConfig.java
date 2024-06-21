package top.whgojp.common.config;

import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import top.whgojp.common.constant.SysConstant;

import java.io.IOException;


/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/23 18:58
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Autowired
    private SysConstant sysConstant;

    //实现资源的虚拟路径和物理路径的映射
    @SneakyThrows
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/file/**")
//                .addResourceLocations("file:/Users/whgojp/Desktop/Security/JAVA/JavaSecLab/target/classes/static/upload/xss/");
                .addResourceLocations("file:" + sysConstant.uploadFolder);
        registry.addResourceHandler("/static/**")
                .addResourceLocations("classpath:/static/");
    }
}
