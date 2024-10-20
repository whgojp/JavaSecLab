package top.whgojp.modules.sqli.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @description ORM框架-JPA下的sql注入问题
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/28 10:20
 */
@Api(value = "JPAController",tags = "SQL注入3-JPA")
@Controller
@RequestMapping("/sqli/jpa")
public class JPAController {
    @RequestMapping("")
    public String sqliJdbc(){
        return "vul/sqli/jpa";
    }
}
