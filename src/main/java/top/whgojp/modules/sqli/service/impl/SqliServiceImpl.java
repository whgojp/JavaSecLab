package top.whgojp.modules.sqli.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import io.swagger.models.auth.In;
import org.apache.ibatis.annotations.Options;
import org.springframework.beans.factory.annotation.Autowired;
import top.whgojp.modules.sqli.entity.Sqli;
import top.whgojp.modules.sqli.mapper.SqliMapper;
import top.whgojp.modules.sqli.service.SqliService;
import org.springframework.stereotype.Service;

import java.util.List;

/**
* @author whgojp
* @description 针对表【users】的数据库操作Service实现
* @createDate 2024-04-29 14:18:13
*/
@Service
public class SqliServiceImpl extends ServiceImpl<SqliMapper, Sqli>
    implements SqliService {
    @Autowired
    private SqliMapper sqliMapper;

    @Override
    public int nativeInsert(Sqli user) {
        return sqliMapper.insert(user);
    }

    @Override
    public int nativeDelete(Integer id) {
        return sqliMapper.deleteById(id);
    }

    @Override
    @Options(useCache = false)
    public int nativeUpdate(Sqli user) {
        return sqliMapper.updateById(user);
    }

    @Override
    public Sqli nativeSelect(Integer id) {
        return sqliMapper.selectById(id);
    }

    //自定义SQL-使用#{}
    @Override
    public int customInsert(Sqli user) {
        return sqliMapper.customInsert(user);
    }

    @Override
    public int customDelete(Integer id) {
        return sqliMapper.customDelete(id);
    }

    @Override
    public int customUpdate(Sqli user) {
        return sqliMapper.customUpdate(user);
    }

    @Override
    public Sqli customSelect(Integer id) {
        return sqliMapper.customSelect(id);
    }

    @Override
    public List<Sqli> orderByVul(String field) {
        return sqliMapper.orderByVul(field);
    }

    @Override
    public List<Sqli> orderByPrepareStatement(String field) {
        return sqliMapper.orderByPrepareStatement(field);
    }

    @Override
    public List<Sqli> orderByWriteList(String field) {
        return sqliMapper.orderByWriteList(field);
    }

    @Override
    public List<Sqli> likeVul(String keyword) {
        return sqliMapper.likeVul(keyword);
    }

    @Override
    public List<Sqli> likePrepareStatement(String keyword) {
        return sqliMapper.likePrepareStatement(keyword);
    }

    @Override
    public List<Sqli> inVul(String scope) {
        return sqliMapper.inVul(scope);
    }

    @Override
    public List<Sqli> inPrepareStatement(String scope) {
        return sqliMapper.inPrepareStatement(scope);
    }

    @Override
    public List<Sqli> inSafeForeach(List<Integer> scope) {
        return sqliMapper.inSafeForeach(scope);
    }


}




