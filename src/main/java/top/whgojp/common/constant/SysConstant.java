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

    @Value("${folder.upload:/tmp/upload}")
    private String uploadFolder;

    @Value("${folder.static:/tmp/static}")
    private String staticFolder;

    public SysConstant(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void init() throws IOException {
        // 初始化上传目录
        initializeDirectory(uploadFolder, "upload");

        // 初始化静态资源目录
        initializeDirectory(staticFolder, "static");
    }

    /**
     * 初始化目录，如果不存在则尝试创建
     *
     * @param path          目录路径
     * @param directoryName 目录名称，用于错误提示
     * @throws IOException 如果目录创建失败
     */
    private void initializeDirectory(String path, String directoryName) throws IOException {
        File dir = new File(path);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Failed to create " + directoryName + " directory: " + path);
        }
    }

}