package top.whgojp.modules.injection.sqli.mapper;

import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.annotations.Update;
import org.springframework.stereotype.Repository;
import top.whgojp.modules.injection.sqli.entity.Users;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

/**
* @author whgojp
* @description 针对表【users】的数据库操作Mapper
* @createDate 2024-04-29 14:18:13
* @Entity top.whgojp.modules.injection.sqli.entity.Users
*/
@Repository
public interface UsersMapper extends BaseMapper<Users> {
    //MyBaitsX插件生成
    int customInsert(Users users);

    //复杂业务场景需要手工写sql语句 XML文件
    int customDelete(Integer id);

    //使用注解@(Insert|Delete|Update|Select)
    @Update("UPDATE users SET user = #{username}, pass = #{password} WHERE id = #{id}")
    int customUpdate(Users user);

    //使用@(Insert|Delete|Update|Select)Provider
    @SelectProvider(type = UserSqlProvider.class, method = "selectUserById")
    Users customSelect(Integer id);




}




