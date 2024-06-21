package top.whgojp.security.handler;

import cn.hutool.core.date.DateUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import top.whgojp.common.constant.SysConstant;
import top.whgojp.common.enums.LoginError;
import top.whgojp.common.push.service.EmailPush;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Data
@Slf4j
@Component
public class CustomSimpleUrlAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private static final String DEFAULT_FAILURE_URL = SysConstant.LOGIN_URL;

    private String defaultFailureUrl;

    private EmailPush emailPush;


    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        super.onAuthenticationFailure(request, response, exception);
        setDefaultFailureUrl(determineFailureUrl(exception));
        log.info("当前异常："+exception.getMessage());

        String loginIp = request.getRemoteHost();
        String loginDate = DateUtil.now();

        log.info("IP:{} 于 {} 尝试登录系统失败 失败原因:{}", loginIp, loginDate, exception.getMessage());

        try {
            // 发邮件
            this.emailPush.send();

        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }
    }
    public void CustomOnAuthenticationFailure(Exception exception){

    }
    private String determineFailureUrl(AuthenticationException exception) {
        // 默认设置登录错误页面为/login
        defaultFailureUrl = StringUtils.hasLength(defaultFailureUrl) ? defaultFailureUrl : DEFAULT_FAILURE_URL;

        Integer failureType = determineFailureType(exception).getType();

        if (failureType != null) {
            defaultFailureUrl += defaultFailureUrl.lastIndexOf("?") > 0 ? "&" : "?" + "error=" + failureType;
        }

        return defaultFailureUrl;
    }

    private LoginError determineFailureType(AuthenticationException exception) {
        if (exception.getMessage() == "验证码为空"){
            return LoginError.CAPTCHANOTFOUND;
        } else if (exception.getMessage() == "验证码过期") {
            return LoginError.CAPTCHAEXPIRED;
        } else if (exception.getMessage() == "验证码不正确") {
            return LoginError.CAPTCHAERROR;
        } else if (exception instanceof UsernameNotFoundException) {
            return LoginError.USERNAMENOTFOUND;
        } else if (exception instanceof LockedException) {
            return LoginError.LOCKED;
        } else if (exception instanceof AccountExpiredException) {
            return LoginError.ACCOUNTEXPIRED;
        } else if (exception instanceof BadCredentialsException) {
            return LoginError.BADCREDENTIALS;
        }

        return LoginError.FAILURE;
    }


    public String getDefaultFailureUrl() {
        return defaultFailureUrl;
    }

    @Override
    public void setDefaultFailureUrl(String defaultFailureUrl) {
        super.setDefaultFailureUrl(defaultFailureUrl);
    }

}
