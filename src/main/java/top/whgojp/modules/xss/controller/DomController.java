package top.whgojp.modules.xss.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @description 跨站脚本-Dom型XSS
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/23 17:25
 */
@Slf4j
@Api(value = "ReflectController", tags = "跨站脚本-Dom型XSS")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/xss/dom")
public class DomController {
    @RequestMapping("")
    public String xssDom() {
        return "vul/xss/dom";
    }
    @RequestMapping("/href")
    public String xssDomHref() {
        return "vul/xss/dom-href";
    }
}
