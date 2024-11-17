package top.whgojp.common.constant;

import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.File;
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

    @Value("${upload.folder:/tmp/upload}") // 容器内部固定路径，默认值为/tmp/upload
    private String uploadFolder;

    private String staticFolder;

    public SysConstant(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }


    @PostConstruct
    public void init() throws IOException {
        // 获取资源对象
        File uploadDir = new File(uploadFolder);
        if (!uploadDir.exists()) {
            if (!uploadDir.mkdirs()) {
                throw new IOException("Failed to create upload directory: " + uploadFolder);
            }
        }

//        Resource uploadResource = resourceLoader.getResource("classpath:/static/upload/");
        Resource staticResource = resourceLoader.getResource("classpath:/static/");
        if (staticResource.exists()) {
            try {
                this.staticFolder = staticResource.getFile().getPath();
            } catch (IOException e) {
                this.staticFolder = staticResource.getURL().toString();
            }
        } else {
            throw new IOException("Resource not found!");
        }
    }

}