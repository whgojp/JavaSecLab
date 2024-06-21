package top.whgojp.security.handler;

import cn.hutool.core.date.DateUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import top.whgojp.common.event.LoginLogEvent;
import top.whgojp.common.push.service.EmailPush;
import top.whgojp.common.push.service.SmsPush;
import top.whgojp.common.push.service.WechatPush;
import top.whgojp.common.utils.IPUtils;
import top.whgojp.common.utils.SpringContextUtils;
import top.whgojp.modules.system.entity.Log;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Date;

@Data
@Slf4j
public class CustomSavedRequestAwareAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private EmailPush emailPush;

    private SmsPush smsPush;

    private WechatPush wechatPush;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        super.onAuthenticationSuccess(request, response, authentication);
        String username = authentication.getName();
        String loginIp = request.getRemoteHost();
        String loginDate = DateUtil.now();

        log.info("用户名:{},于{} 成功登录系统 IP:{} session:{}", username, loginDate, loginIp,authentication.getDetails());

        // 登录日志记录
        final Log loginLog = new Log();
        loginLog.setOptionip(IPUtils.getIpAddr(request));
        loginLog.setOptionname("用户登录成功");
        loginLog.setOptionterminal(request.getHeader("User-Agent"));
        loginLog.setUsername(username);
        loginLog.setOptiontime(new Date());
        SpringContextUtils.publishEvent(new LoginLogEvent(loginLog));

        try {
            // 发邮件
            this.emailPush.send();

        } catch (Exception ex) {
            log.error(ex.getMessage(),ex);
        }
    }

}
