package top.whgojp.modules.springboot.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;

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

}
