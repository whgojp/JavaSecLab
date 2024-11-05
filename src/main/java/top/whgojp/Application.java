package top.whgojp;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;


@Slf4j
@SpringBootApplication
public class Application {


//    @SneakyThrows
    public static void main(String[] args) throws IOException {
        System.setProperty("org.apache.commons.collections.enableUnsafeSerialization", "true");



        SpringApplication.run(Application.class, args);
        log.info("==================JavaSecLab启动成功================");
    }

}
