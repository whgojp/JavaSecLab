package top.whgojp.modules.injection.sqli.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @description ORM框架-Hibernate下的sql注入问题
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/28 10:13
 */
@Api(value = "HibernateController",tags = "SQL注入4-Hibernate")
@Controller
@RequestMapping("/sqli/hibernate")
public class HibernateController {
    @ApiOperation("test")
    @GetMapping("/test")
    @ResponseBody
    public String test(){
        return "index";
    }
}
