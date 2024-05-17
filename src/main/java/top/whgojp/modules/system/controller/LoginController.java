package top.whgojp.modules.system.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @description 登录处理
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/16 21:45
 */
@Slf4j
@Controller
public class LoginController {
    @RequestMapping({"/","/index"})
    public String index(){
        return "/index.html";
    }


}
