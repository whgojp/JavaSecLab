package top.whgojp.modules.loginconfront.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

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
    @RequestMapping("")
    public String bypass() {
        return "vul/loginconfront/bypass";
    }

    @RequestMapping("/reset")
    public String reset() {
        return "vul/loginconfront/resetpass";
    }

    // 测试账号密码
    final String REAL_USERNAME = "admin";
    final String REAL_PASSWORD = "admin123";

    @PostMapping("/vul1step1")
    @ResponseBody
    public R vul1step1(String username, String password) {
        if (REAL_USERNAME.equalsIgnoreCase(username) && REAL_PASSWORD.equalsIgnoreCase(password)) {
            return R.ok("账号校验通过，请稍等！");
        } else {
            return R.error("账号校验失败，请重试！");
        }
    }

    @PostMapping("/vul1step2")
    @ResponseBody
    public R vul1step2(String code) {
        if ("0".equals(code)) {
            return R.ok("登录成功，欢迎！");
        } else {
            return R.error("登录失败！");
        }
    }


    private final Map<Integer, String> stepData = new HashMap<>();

    private final String oladPass = "!@#qwf@3123";

    // step1:验证用户名
    @PostMapping("/step1")
    @ResponseBody
    public R vul2Step1(@RequestParam String username) {
        try {
            log.info("用户名：" + username);
            if (username.isEmpty()) {
                return R.error("用户名不能为空");
            }
            stepData.put(1, username);
            return R.ok("用户名验证成功！");
        } catch (Exception e) {
            return R.error("服务器错误，请稍后再试");
        }
    }


    // step2:验证旧密码
    @PostMapping("/step2")
    @ResponseBody
    public R vul2Step2(@RequestParam String oldPassword) {
        if (oldPassword.isEmpty()) {
            return R.error("旧密码不能为空！");
        }
        if (!oladPass.equals(oldPassword)) {
            return R.error("旧密码错误！");
        }
        stepData.put(2, oldPassword);
        return R.ok("密码验证成功！");
    }

    // step3:设置新密码
    @PostMapping("/step3")
    @ResponseBody
    public R vul2Step3(@RequestParam String newPassword) {
        if (newPassword.length() < 6) {
            return R.error("密码长度必须大于6!");
        }
        stepData.put(3, newPassword);
        System.out.println("表单数据: " + stepData);
        return R.ok("密码重置成功！");
    }

}
