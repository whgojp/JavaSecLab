package top.whgojp.modules.system.controller;

import io.swagger.annotations.Api;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;
import top.whgojp.modules.system.entity.User;
import top.whgojp.modules.system.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * @description 已登录用户相关接口
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/24 11:23
 */
@Controller
@Api(value = "SysController", tags = "系统管理-相关接口")
@RequestMapping("/system")
@CrossOrigin(origins = "*")
public class SysController {
    @Autowired
    private UserService userService;


    @GetMapping("/password")
    public String chPwdView() {
        return "system/password";
    }

    @PostMapping("/chpwd")
    @ResponseBody
    public R changePassword(@RequestParam String old_password, @RequestParam String new_password, @RequestParam String again_password) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        if (old_password == null || new_password == null || again_password == null) {
            return R.error("输入不能为空!");
        }
        if (old_password.equals(new_password)) {
            return R.error("新密码不能与旧密码一致!");
        }
        if (!new_password.equals(again_password)) {
            return R.error("新密码两次输入不一致!");
        }

        // 使用旧密码尝试登录
        User user = userService.userLogin(username, old_password);
        if (user != null) {
            if (userService.changePassword(username, new_password) != 0) {
//                session.invalidate();
                return R.ok("密码修改成功");
            } else {
                return R.error("密码修改失败!");
            }
        } else {
            return R.error("旧密码输入错误!");
        }

    }
}
