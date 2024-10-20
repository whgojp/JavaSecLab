package upload;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.SpringBootTestContextBootstrapper;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.context.BootstrapWith;
import top.whgojp.Application;

import java.net.URL;

@SpringBootTest(classes = Application.class)
public class UploadTest {

    @Autowired
    private ResourceLoader resourceLoader;

    @Test
    @SneakyThrows
    public void test01() {
        // 获取网站根目录
        String uploadFolder = resourceLoader.getResource("classpath:/static/upload/xss/").getFile().getPath();
        System.out.println(uploadFolder);
    }
}