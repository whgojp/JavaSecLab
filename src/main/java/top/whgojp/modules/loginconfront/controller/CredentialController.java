package top.whgojp.modules.loginconfront.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import top.whgojp.common.utils.R;

/**
 * @description 登录对抗-凭证安全
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/11/19 22:28
 */
@Slf4j
@Api(value = "CredentialController", tags = "登录对抗-凭证安全")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/loginconfront/credential")
public class CredentialController {
    @RequestMapping("")
    public String credential() {
        return "vul/loginconfront/credential";
    }

    @RequestMapping("/vul1")
    public R vul1() {
        return R.ok();
    }

    @RequestMapping("/vul2")
    public R vul2() {
        return R.ok();
    }

}
