package top.whgojp.security.detail;

import cn.hutool.core.util.ObjectUtil;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import top.whgojp.modules.system.entity.User;
import top.whgojp.modules.system.service.UserService;
import top.whgojp.security.handler.CustomSimpleUrlAuthenticationFailureHandler;

import java.util.*;

/**
 * @Description //TODO $
 * @Date 21:09
 * @Author whgojp@foxmail.com
 **/
@Slf4j
@Component
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserService userService;
    @Autowired
    private CustomSimpleUrlAuthenticationFailureHandler customSimpleUrlAuthenticationFailureHandler;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User sysUser = userService.getOne(Wrappers.<User>query().lambda().eq(User::getUsername, username));
        if (ObjectUtil.isNull(sysUser)) {
            throw new UsernameNotFoundException("用户不存在");
        }

        // 用户存在，直接返回 UserDetails 对象，不处理角色信息

        return new org.springframework.security.core.userdetails.User(sysUser.getUsername(), sysUser.getPassword(), new ArrayList<>());
    }

}
