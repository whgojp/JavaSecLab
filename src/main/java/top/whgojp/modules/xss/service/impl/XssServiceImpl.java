package top.whgojp.modules.xss.service.impl;

import cn.hutool.core.date.DateUtil;
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
public class XssServiceImpl extends ServiceImpl<XssMapper, Xss> implements XssService {
    @Autowired
    private XssMapper xssMapper;

    @Override
    public int insertOne(String content, String ua) {
        try {
            log.info("插入XSS记录 - content: {}, ua: {}", content, ua);
            final int code = xssMapper.insertAll(content,ua,DateUtil.now());
            return code;
        } catch (Exception e) {
            log.error("插入XSS记录失败", e);
            return 0;
        }
    }

    @Override
    public List<Xss> selectAll() {
        try {
            List<Xss> xssList = xssMapper.selectAll();
            return xssList;
        } catch (Exception e) {
            log.error("查询XSS记录失败", e);
            return null;
        }
    }

    @Override
    public int deleteById(int id) {
        try {
            log.info("删除XSS记录 - id: {}", id);
            int i = xssMapper.deleteById(id);
            return i;
        } catch (Exception e) {
            log.error("删除XSS记录失败 - id: {}", id, e);
            return 0;
        }
    }
}
