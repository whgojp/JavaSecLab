package top.whgojp.modules.loginconfront.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
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
    private static final Set<String> REAL_USERNAMES = new HashSet<>(Arrays.asList("admin", "test", "12345", "root"));
    private static final String REAL_PASSWORD = "admin123";
    private final MessageSource messageSource;

    public AccountController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String account() {
        return "vul/loginconfront/account";
    }

    @RequestMapping("/vul1")
    @ResponseBody
    public R vul1(String username, String password) {
        if (username == null || username.trim().isEmpty() || password == null) {
            return R.error(msg("login.account.result.empty"));
        }
        if (REAL_USERNAMES.contains(username)) {
            if (REAL_PASSWORD.equalsIgnoreCase(password)) {
                return R.ok(msg("login.account.result.success", username, password));
            } else {
                return R.error(msg("login.account.result.passwordWrong"));
            }
        } else {
            return R.error(msg("login.account.result.userMissing"));
        }
    }

    @RequestMapping("/vul2")
    @ResponseBody
    public R vul2(String username, String password) {
        if (username == null || username.trim().isEmpty() || password == null) {
            return R.error(msg("login.account.result.empty"));
        }
        // 这里简单模拟下数据库查询操作
        // User user = UserService.getAllByUsernameAndPassword(username,password)
        if ("admin".equalsIgnoreCase(username) && "admin".equalsIgnoreCase(password)) {
            return R.ok(msg("login.account.result.success", username, password));
        } else {
            return R.ok(msg("login.account.result.genericWrong"));
        }
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

}
