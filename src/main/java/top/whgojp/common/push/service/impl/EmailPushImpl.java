package top.whgojp.common.push.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import top.whgojp.common.push.service.EmailPush;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/14 16:09
 */
@Slf4j
@Service
public class EmailPushImpl implements EmailPush {
    @Override
    public void send() {
        log.info("短信发送成功！");
    }
}
