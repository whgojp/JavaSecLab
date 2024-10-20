package top.whgojp.modules.xss.service;

import top.whgojp.modules.xss.entity.Xss;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

/**
* @author whgojp
* @description 针对表【xss】的数据库操作Service
* @createDate 2024-06-10 14:56:44
*/
public interface XssService extends IService<Xss> {
    int insertOne(String content,String ua);

    List<Xss> selectAll();

    int deleteById(int id);
}
