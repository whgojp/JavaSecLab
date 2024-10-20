package top.whgojp.modules.xss.mapper;
import org.apache.ibatis.annotations.Param;

import org.springframework.stereotype.Repository;
import top.whgojp.modules.xss.entity.Xss;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import java.util.List;

/**
* @author whgojp
* @description 针对表【xss】的数据库操作Mapper
* @createDate 2024-06-10 14:56:44
* @Entity top.whgojp.modules.xss.entity.Xss
*/
@Repository
public interface XssMapper extends BaseMapper<Xss> {

    int insertAll(String content,String ua,String date);

    List<Xss> selectAll();

    int deleteById(@Param("id") Integer id);

}




