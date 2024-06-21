package top.whgojp;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.io.ResourceLoader;
import org.springframework.scheduling.annotation.EnableScheduling;

@Slf4j
@SpringBootApplication
public class Application {
//    @Autowired
//    public static ResourceLoader resourceLoader;
//    public static String uploadFolder;

//    @SneakyThrows
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
//        uploadFolder = resourceLoader.getResource("classpath:static/upload/xss/").getFile().getPath();

        log.info("==================SpringBoot启动成功================");
    }

}
