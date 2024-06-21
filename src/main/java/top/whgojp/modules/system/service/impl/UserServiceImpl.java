package top.whgojp.modules.system.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import top.whgojp.modules.system.entity.User;
import top.whgojp.modules.system.service.UserService;
import top.whgojp.modules.system.mapper.UserMapper;
import org.springframework.stereotype.Service;

/**
* @author whgojp
* @description 针对表【user】的数据库操作Service实现
* @createDate 2024-06-13 20:53:06
*/
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User>
    implements UserService{

}




