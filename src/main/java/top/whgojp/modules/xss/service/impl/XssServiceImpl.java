package top.whgojp.modules.xss.service.impl;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.lang.UUID;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import top.whgojp.modules.xss.entity.Xss;
import top.whgojp.modules.xss.service.XssService;
import top.whgojp.modules.xss.mapper.XssMapper;
import org.springframework.stereotype.Service;

import java.util.List;

/**
* @author whgojp
* @description 针对表【xss】的数据库操作Service实现
* @createDate 2024-06-10 14:56:44
*/
@Slf4j
@Service
public class XssServiceImpl extends ServiceImpl<XssMapper, Xss>
    implements XssService{
    @Autowired
    private XssMapper xssMapper;

    @Override
    public int insertOne(String content) {
        final int code = xssMapper.insertAll(content,DateUtil.now());
        return code;
    }

    @Override
    public List<Xss> selectAll() {
        List<Xss> xssList = xssMapper.selectAll();
        return xssList;
    }
}




