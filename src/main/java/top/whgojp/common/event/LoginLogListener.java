package top.whgojp.common.event;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import top.whgojp.modules.system.entity.Log;
import top.whgojp.modules.system.service.LogService;

/**
 * @Description //TODO $
 * @Date 11:28
 * @Author whgojp@foxmail.com
 **/
@Configuration
@RequiredArgsConstructor
public class LoginLogListener {

    private final LogService logService;

    @Async
    @EventListener(LoginLogEvent.class)
    public void saveSysLog(LoginLogEvent event) {
        Log loginLog = (Log) event.getSource();
        logService.save(loginLog);
    }

}
