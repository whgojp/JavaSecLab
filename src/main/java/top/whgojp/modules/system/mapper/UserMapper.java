package top.whgojp.modules.system.mapper;

import org.springframework.stereotype.Repository;
import top.whgojp.modules.system.entity.User;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

/**
* @author whgojp
* @description 针对表【user】的数据库操作Mapper
* @createDate 2024-06-13 20:53:06
* @Entity top.whgojp.modules.system.entity.User
*/
@Repository
public interface UserMapper extends BaseMapper<User> {

}




