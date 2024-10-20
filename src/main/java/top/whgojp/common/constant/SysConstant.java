package top.whgojp.common.constant;

import lombok.Data;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.IOException;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/23 20:46
 */

import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import lombok.Data;

import javax.annotation.PostConstruct;
import java.io.IOException;

@Component
@Data
public class SysConstant {
    public static final String LOGIN_URL = "/login";
    public static final String LOGIN_PROCESS = "/loginProcess";
    public static final String LOGOUT_URL = "/logout";
    public static final String JWT_AUTH = "/authenticate";

    @Autowired
    private ResourceLoader resourceLoader;

    private String uploadFolder;
    private String staticFolder;

    @PostConstruct
    public void init() throws IOException {
        // 获取资源对象
        Resource uploadResource = resourceLoader.getResource("classpath:/static/upload/");
        Resource staticResource = resourceLoader.getResource("classpath:/static/");
        if (uploadResource.exists() && staticResource.exists()) {
            try {
                this.uploadFolder = uploadResource.getFile().getPath();  // 仅在资源存在于文件系统中时有效
                this.staticFolder = staticResource.getFile().getPath();
            } catch (IOException e) {
                this.uploadFolder = uploadResource.getURL().toString(); // 获取资源的URL
                this.staticFolder = staticResource.getURL().toString();
            }
        } else {
            throw new IOException("Resource not found!");
        }
    }

}