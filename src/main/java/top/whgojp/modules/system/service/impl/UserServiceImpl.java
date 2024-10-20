package top.whgojp.modules.system.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import top.whgojp.modules.system.entity.User;
import top.whgojp.modules.system.service.UserService;
import top.whgojp.modules.system.mapper.UserMapper;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author whgojp
 * @description 针对表【user】的数据库操作Service实现
 * @createDate 2024-06-13 20:53:06
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User>
        implements UserService {
    @Autowired
    private UserMapper userMapper;

    @Override
    public User userLogin(String username, String oldPassword) {
        User user = userMapper.selectByUsernameAndPassword(username, oldPassword);
        return user;
    }

    @Override
    public int changePassword(String username, String newPass) {
        int code = userMapper.updatePasswordByUsername(username, newPass);
        return code;
    }

}




