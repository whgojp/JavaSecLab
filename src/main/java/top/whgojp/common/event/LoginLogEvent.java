package top.whgojp.common.event;

import org.springframework.context.ApplicationEvent;
import top.whgojp.modules.system.entity.Log;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/14 18:14
 */
public class LoginLogEvent extends ApplicationEvent {

    public LoginLogEvent(Log source) {
        super(source);
    }
}
