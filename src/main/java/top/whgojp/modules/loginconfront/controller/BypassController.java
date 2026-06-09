package top.whgojp.modules.loginconfront.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpSession;
import java.util.*;

/**
 * @description 登录对抗-登录绕过
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/11/19 21:01
 */
@Slf4j
@Api(value = "BypassController", tags = "登录对抗-登录绕过")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/loginconfront/bypass")
public class BypassController {
    private final MessageSource messageSource;

    public BypassController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String bypass() {
        return "vul/loginconfront/bypass";
    }

    @RequestMapping("/reset")
    public String reset() {
        return "vul/loginconfront/resetpass";
    }

    // 测试账号密码
    private static final String REAL_USERNAME = "admin";
    private static final String REAL_PASSWORD = "admin123";
    private static final String RESET_FLOW_DATA = "loginconfrontResetFlowData";

    @PostMapping("/vul1step1")
    @ResponseBody
    public R vul1step1(String username, String password) {
        if (username == null || username.trim().isEmpty() || password == null) {
            return R.error(msg("login.bypass.result.accountFailed"));
        }
        if (REAL_USERNAME.equalsIgnoreCase(username) && REAL_PASSWORD.equalsIgnoreCase(password)) {
            return R.ok(msg("login.bypass.result.accountPassed"));
        } else {
            return R.error(msg("login.bypass.result.accountFailed"));
        }
    }

    @PostMapping("/vul1step2")
    @ResponseBody
    public R vul1step2(String code) {
        if ("0".equals(code)) {
            return R.ok(msg("login.bypass.result.loginSuccess"));
        } else {
            return R.error(msg("login.bypass.result.loginFailed"));
        }
    }

    private static final String OLD_PASS = "!@#qwf@3123";

    // step1:验证用户名
    @PostMapping("/step1")
    @ResponseBody
    public R vul2Step1(@RequestParam String username, HttpSession session) {
        try {
            log.info("Password reset username: {}", username);
            if (username == null || username.trim().isEmpty()) {
                return R.error(msg("login.bypass.result.usernameEmpty"));
            }
            flowData(session).put(1, username);
            return R.ok(msg("login.bypass.result.usernamePassed"));
        } catch (Exception e) {
            return R.error(msg("login.bypass.result.serverError"));
        }
    }


    // step2:验证旧密码
    @PostMapping("/step2")
    @ResponseBody
    public R vul2Step2(@RequestParam String oldPassword, HttpSession session) {
        if (oldPassword == null || oldPassword.isEmpty()) {
            return R.error(msg("login.bypass.result.oldPasswordEmpty"));
        }
        if (!OLD_PASS.equals(oldPassword)) {
            return R.error(msg("login.bypass.result.oldPasswordWrong"));
        }
        flowData(session).put(2, oldPassword);
        return R.ok(msg("login.bypass.result.oldPasswordPassed"));
    }

    // step3:设置新密码
    @PostMapping("/step3")
    @ResponseBody
    public R vul2Step3(@RequestParam String newPassword, HttpSession session) {
        if (newPassword == null || newPassword.length() < 6) {
            return R.error(msg("login.bypass.result.newPasswordShort"));
        }
        Map<Integer, String> stepData = flowData(session);
        stepData.put(3, newPassword);
        log.info("Password reset flow data: {}", stepData);
        return R.ok(msg("login.bypass.result.resetSuccess"));
    }

    @SuppressWarnings("unchecked")
    private Map<Integer, String> flowData(HttpSession session) {
        Object data = session.getAttribute(RESET_FLOW_DATA);
        if (data instanceof Map) {
            return (Map<Integer, String>) data;
        }
        Map<Integer, String> stepData = new HashMap<>();
        session.setAttribute(RESET_FLOW_DATA, stepData);
        return stepData;
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

}
