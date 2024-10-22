package top.whgojp.modules.components.log4j2.controller;

import io.swagger.annotations.Api;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.text.StringEscapeUtils;


/**
 * @description 组件漏洞-Log4j2
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/12 22:52
 */
@Api(value = "Log4j2Controller", tags = "组件漏洞-Log4j2")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/log4j2")
public class Log4j2Controller {
    @RequestMapping("")
    public String log4j2() {
        return "vul/components/log4j2";
    }

    private static final Logger logger = LogManager.getLogger(Log4j2Controller.class);

    @PostMapping("/vul")
    @ResponseBody
    public String vulLog4j2(@RequestParam("payload") String payload) {
        System.out.println("[+]Log4j2反序列化："+payload);
        logger.error(payload);
        return "[+]Log4j2反序列化："+payload;
    }

    @PostMapping("/safe")
    @ResponseBody
    public String safeLog4j2(@RequestParam("payload") String payload) {
        payload = StringEscapeUtils.escapeHtml4(payload);

        System.out.println("[+]Log4j2反序列化："+payload);
        logger.error(payload);
        return "[+]Log4j2反序列化："+payload;
    }



}
