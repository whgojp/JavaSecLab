package top.whgojp.common.constant;

import lombok.Data;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/23 20:46
 */
@Component
@Data
public class SysConstant {
    public static final String LOGIN_URL = "/login";
    public static final String LOGIN_PROCESS = "/loginProcess";
    public static final String LOGOUT_URL = "/logout";
    public static final String JWT_AUTH = "/authenticate";



    @Autowired
    public static ResourceLoader resourceLoader;
    public static String uploadFolder;


    @SneakyThrows
    public static void main(String[] args) {
        uploadFolder = resourceLoader.getResource("classpath:static/upload/xss/").getFile().getPath();
    }

}
