package top.whgojp.common.config;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;
import top.whgojp.common.constant.SysConstant;

/**
 * @description 自定义静态资源的访问路径、文件映射
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/23 18:58
 */

@Slf4j
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private SysConstant sysConstant;
    @SneakyThrows
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        String uploadFolderPath = sysConstant.getUploadFolder();
        registry.addResourceHandler("/file/**")
                .addResourceLocations("file:" + uploadFolderPath + "/");
        registry.addResourceHandler("/static/**")
                .addResourceLocations("classpath:/static/");
    }

}
