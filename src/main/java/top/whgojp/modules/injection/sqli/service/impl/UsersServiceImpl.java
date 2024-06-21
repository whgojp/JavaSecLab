package top.whgojp.modules.injection.sqli.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.apache.ibatis.annotations.Options;
import org.springframework.beans.factory.annotation.Autowired;
import top.whgojp.modules.injection.sqli.entity.Users;
import top.whgojp.modules.injection.sqli.service.UsersService;
import top.whgojp.modules.injection.sqli.mapper.UsersMapper;
import org.springframework.stereotype.Service;

/**
* @author whgojp
* @description 针对表【users】的数据库操作Service实现
* @createDate 2024-04-29 14:18:13
*/
@Service
public class UsersServiceImpl extends ServiceImpl<UsersMapper, Users>
    implements UsersService{
    @Autowired
    private UsersMapper usersMapper;

    @Override
    public int nativeInsert(Users user) {
        return usersMapper.insert(user);
    }

    @Override
    public int nativeDelete(Integer id) {
        return usersMapper.deleteById(id);
    }

    @Override
    @Options(useCache = false)
    public int nativeUpdate(Users user) {
        return usersMapper.updateById(user);
    }

    @Override
    public Users nativeSelect(Integer id) {
        return usersMapper.selectById(id);
    }

    @Override
    public int customInsert(Users user) {
        return usersMapper.customInsert(user);
    }

    @Override
    public int customDelete(Integer id) {
        return usersMapper.customDelete(id);
    }

    @Override
    public int customUpdate(Users user) {
        return usersMapper.customUpdate(user);
    }

    @Override
    public Users customSelect(Integer id) {
        return usersMapper.customSelect(id);
    }

}




