package top.whgojp.security.handler;

import cn.hutool.core.date.DateUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;

@Data
@Slf4j
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        super.onLogoutSuccess(request, response, authentication);
        String username = authentication.getName();
        String loginIp = request.getRemoteHost();
        String loginDate = DateUtil.now();


        log.info("用户名:{},于{} 成功退出系统 IP:{}", username, loginDate, loginIp);

        try {
            // 发邮件
//            this.emailPush.send();

        } catch (Exception ex) {
            log.error(ex.getMessage(),ex);
        }
    }
}
