package top.whgojp.modules.sqli.service;

import io.swagger.models.auth.In;
import top.whgojp.modules.sqli.entity.Sqli;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

/**
* @author whgojp
* @description 针对表【users】的数据库操作Service
* @createDate 2024-04-29 14:18:13
*/
public interface SqliService extends IService<Sqli> {
    //MyBatis自带方法
    int nativeInsert(Sqli user);
    int nativeDelete(Integer id);
    int nativeUpdate(Sqli user);
    Sqli nativeSelect(Integer id);

    //自定义SQL-使用#{}
    int customInsert(Sqli user);
    int customDelete(Integer id);
    int customUpdate(Sqli user);
    Sqli customSelect(Integer id);

    // Order by下的${}拼接注入问题
    List<Sqli> orderByVul(String field);
    // Order by下的#{}写法 排序不生效
    List<Sqli> orderByPrepareStatement(String field);
    // Order by下的安全写法 白名单
    List<Sqli> orderByWriteList(String field);

    // 模糊查询
    List<Sqli> likeVul(String keyword);
    List<Sqli> likePrepareStatement(String keyword);

    // in 之后的多个参数
    List<Sqli> inVul(String scope);
    List<Sqli> inPrepareStatement(String scope);
    List<Sqli> inSafeForeach(List<Integer> scope);

}
