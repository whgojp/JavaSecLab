package top.whgojp.modules.loginconfront.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.apache.regexp.RE;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @description 登录对抗-账号安全
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/8 23:16
 */
@Slf4j
@Api(value = "AccountController", tags = "登录对抗-账号安全")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/loginconfront/account")
public class AccountController {
    // 测试账号密码
    final Set<String> REAL_USERNAMES = new HashSet<>(Arrays.asList("admin", "test", "12345", "root"));
    final String REAL_PASSWORD = "admin123";

    @RequestMapping("")
    public String account() {
        return "vul/loginconfront/account";
    }

    @RequestMapping("/vul1")
    @ResponseBody
    public R vul1(String username, String password) {
        if (REAL_USERNAMES.contains(username)) {
            if (REAL_PASSWORD.equalsIgnoreCase(password)) {
                return R.ok("登录成功！用户名：" + username + ", 密码：" + password);
            } else {
                return R.error("密码错误，请重试！");
            }
        } else {
            return R.error("用户不存在！");
        }
    }

    @RequestMapping("/vul2")
    @ResponseBody
    public R vul2(String username, String password) {
        // 这里简单模拟下数据库查询操作
        // User user = UserService.getAllByUsernameAndPassword(username,password)
        if ("admin".equalsIgnoreCase(username) && "admin".equalsIgnoreCase(password)) {
            return R.ok("登录成功！用户名：" + username + ", 密码：" + password);
        } else {
            return R.ok("账号或密码错误！");
        }
    }


}
