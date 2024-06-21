package top.whgojp.modules.system.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import top.whgojp.modules.system.entity.Log;
import top.whgojp.modules.system.service.LogService;
import top.whgojp.modules.system.mapper.LogMapper;
import org.springframework.stereotype.Service;

/**
* @author whgojp
* @description 针对表【log】的数据库操作Service实现
* @createDate 2024-06-14 17:54:54
*/
@Service
public class LogServiceImpl extends ServiceImpl<LogMapper, Log>
    implements LogService{

}




