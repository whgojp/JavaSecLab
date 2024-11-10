package top.whgojp.modules.logic.idor.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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

    @RequestMapping("")
    public String horizontal(){
        return "vul/logic/idor/horizontal";
    }

    @GetMapping("/getUserInfo")
    @ResponseBody
    public R getUserInfo(String username){
        User user = userMapper.getAllByUsername(username);
        if (user!=null){
            return R.ok("用户名："+user.getUsername()+" 密码："+user.getPassword());
        }else return R.error("用户名不存在");
    }
    @GetMapping("/safe")
    @ResponseBody
    public R safe(String username){
        // 获取当前登录的用户名
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        // 检查当前请求的用户名是否和登录用户名一致
        if (!username.equals(currentUsername)) {
            return R.error("您没有权限查看该用户的资料,当前登录用户："+currentUsername);
        }
        // 查询用户信息
        User user = userMapper.getAllByUsername(username);
        if (user != null) {
            return R.ok("用户名："+user.getUsername()+" 密码："+user.getPassword());
        } else {
            return R.error("用户名不存在");
        }
    }

}
