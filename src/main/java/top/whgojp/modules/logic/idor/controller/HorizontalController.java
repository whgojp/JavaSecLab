package top.whgojp.modules.logic.idor.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;
import top.whgojp.modules.system.entity.User;
import top.whgojp.modules.system.mapper.UserMapper;

/**
 * @description 逻辑漏洞-水平越权
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/28 22:07
 */
@Slf4j
@Api(value = "HorizontalController", tags = "逻辑漏洞-水平越权")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/logic/idor/horizontal")
public class HorizontalController {
    @Autowired
    private UserMapper userMapper;
    @Autowired
    private MessageSource messageSource;

    @RequestMapping("")
    public String horizontal(){
        return "vul/logic/idor/horizontal";
    }

    @GetMapping("/getUserInfo")
    @ResponseBody
    public R getUserInfo(String username){
        User user = userMapper.getAllByUsername(username);
        if (user!=null){
            return R.ok(msg("logic.idor.result.userInfo", user.getUsername(), user.getPassword()));
        }else return R.error(msg("logic.idor.result.userNotFound"));
    }
    @GetMapping("/safe")
    @ResponseBody
    public R safe(String username){
        // Get the current logged-in username.
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        // Check whether the requested username matches the logged-in user.
        if (username == null || !username.equals(currentUsername)) {
            return R.error(msg("logic.idor.result.noPermission", currentUsername));
        }
        // Query user information.
        User user = userMapper.getAllByUsername(username);
        if (user != null) {
            return R.ok(msg("logic.idor.result.userInfo", user.getUsername(), user.getPassword()));
        } else {
            return R.error(msg("logic.idor.result.userNotFound"));
        }
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
