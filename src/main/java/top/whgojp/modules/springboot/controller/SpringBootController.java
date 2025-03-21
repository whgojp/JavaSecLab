package top.whgojp.modules.springboot.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;
import top.whgojp.modules.springboot.entity.MaliciousObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.sql.*;

/**
 * @description java专题-SpringBoot相关漏洞
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/8 23:44
 */
@Slf4j
@Api(value = "SpringBootController", tags = "java专题-SpringBoot相关漏洞")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/springboot")
public class SpringBootController {
    @RequestMapping("")
    public String springboot() {
        return "vul/springboot/springboot";
    }

    @Value("${spring.datasource.url:jdbc:mysql://localhost:13306/JavaSecLab}")
    String url = "";
    @Value("${spring.datasource.username:jdbc:root}")
    String username = "";
    @Value("${spring.datasource.password:jdbc:QWE123qwe}")
    String password = "";

    @RequestMapping("/jdbc")
    @ResponseBody
    public R jdbc() {
        try {
            Connection conn = DriverManager.getConnection(url, username, password);
            String selectQuery = "SELECT malicious_object FROM objects WHERE id = 1";
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(selectQuery);

            if (rs.next()) {
                byte[] maliciousObjectBytes = rs.getBytes("malicious_object");
                // 反序列化恶意对象
                ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(maliciousObjectBytes);
                ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);

                MaliciousObject maliciousObject = (MaliciousObject) objectInputStream.readObject();

                log.info("触发MYSQL-JBDC反序列化漏洞！");
            }

            stmt.close();
            conn.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return R.ok("触发MYSQL-JBDC反序列化漏洞！");
    }

    @RequestMapping("/insert")
    @ResponseBody
    public R insertMaliciousObject(@RequestParam String command) {
        try {
            MaliciousObject maliciousObject = new MaliciousObject(command);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(maliciousObject);
            byte[] objectBytes = baos.toByteArray();

            Connection conn = DriverManager.getConnection(url, username, password);
            String insertQuery = "INSERT INTO objects (id, malicious_object) VALUES (?, ?)";
            PreparedStatement stmt = conn.prepareStatement(insertQuery);
            stmt.setInt(1, 1);
            stmt.setBytes(2, objectBytes);
            stmt.executeUpdate();
            stmt.close();
            conn.close();

            return R.ok("恶意对象插入成功！");
        } catch (Exception e) {
            e.printStackTrace();
            return R.error("恶意对象插入失败(主键冲突的话在请数据库中删除该记录)：" + e.getMessage());
        }
    }

    @RequestMapping("/vul")
    @ResponseBody
    public R vul(String url, String username, String password) {

        try {
//            Class.forName("com.mysql.jdbc.Driver");
             Class.forName("com.mysql.cj.jdbc.Driver");
            DriverManager.getConnection(url,username,password);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return R.ok();
    }


}
