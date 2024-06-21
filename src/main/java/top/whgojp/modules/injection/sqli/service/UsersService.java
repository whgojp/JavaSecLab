package top.whgojp.modules.injection.sqli.service;

import org.springframework.beans.factory.annotation.Autowired;
import top.whgojp.modules.injection.sqli.entity.Users;
import com.baomidou.mybatisplus.extension.service.IService;

/**
* @author whgojp
* @description 针对表【users】的数据库操作Service
* @createDate 2024-04-29 14:18:13
*/
public interface UsersService extends IService<Users> {
    //MyBatis自带方法
    int nativeInsert(Users user);
    int nativeDelete(Integer id);
    int nativeUpdate(Users user);
    Users nativeSelect(Integer id);

    //自定义SQL
    int customInsert(Users user);
    int customDelete(Integer id);
    int customUpdate(Users user);
    Users customSelect(Integer id);


}
