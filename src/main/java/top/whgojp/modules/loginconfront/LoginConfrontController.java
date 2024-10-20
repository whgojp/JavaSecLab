package top.whgojp.modules.loginconfront;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @description 登录框对抗
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/8 23:16
 */
@Slf4j
@Api(value = "LoginConfrontController", tags = "敏感信息泄漏-测试页面")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/loginConfront")
public class LoginConfrontController {
    @RequestMapping("")
    public String CeShi() {
        return "vul/loginconfront/loginConfront";
    }
}
