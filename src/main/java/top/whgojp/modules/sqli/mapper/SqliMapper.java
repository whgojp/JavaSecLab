package top.whgojp.modules.sqli.mapper;

import io.swagger.models.auth.In;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.annotations.Update;
import org.springframework.stereotype.Repository;
import top.whgojp.modules.sqli.entity.Sqli;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import java.util.List;

/**
* @author whgojp
* @description 针对表【users】的数据库操作Mapper
* @createDate 2024-04-29 14:18:13
* @Entity top.whgojp.modules.entity.sqli.Users
*/
@Repository
public interface SqliMapper extends BaseMapper<Sqli> {
    //MyBaitsX插件生成
    //自定义SQL-使用#{}
    int customInsert(Sqli users);

    //复杂业务场景需要手工写sql语句 XML文件
    int customDelete(Integer id);

    //使用注解@(Insert|Delete|Update|Select)
    @Update("UPDATE sqli SET username = #{username}, password = #{password} WHERE id = #{id}")
    int customUpdate(Sqli user);

    //使用@(Insert|Delete|Update|Select)Provider
    @SelectProvider(type = SqliProvider.class, method = "selectUserById")
    Sqli customSelect(Integer id);


    List<Sqli> orderByVul(String field);
    List<Sqli> orderByPrepareStatement(String field);
    List<Sqli> orderByWriteList(String field);

    List<Sqli> likeVul(String keyword);
    List<Sqli> likePrepareStatement(String keyword);

    List<Sqli> inVul(String scope);
    List<Sqli> inPrepareStatement(String scope);
    List<Sqli> inSafeForeach(List<Integer> scope);
}




