package top.whgojp.common.filter;

import cn.hutool.core.util.StrUtil;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import top.whgojp.common.constant.SysConstant;
import top.whgojp.common.exception.CustomAuthenticationException;
import top.whgojp.security.handler.CustomSimpleUrlAuthenticationFailureHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/21 19:45
 */
@Slf4j
public class ValidateCodeFilter extends OncePerRequestFilter {
    private AntPathMatcher pathMatcher = new AntPathMatcher();
    private CustomSimpleUrlAuthenticationFailureHandler customSimpleUrlAuthenticationFailureHandler;

    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String url = request.getRequestURI();
        if (pathMatcher.match(SysConstant.LOGIN_URL, url)) {
            final String captchaCheck = "11111";
            String captcha = request.getParameter("captcha");
            if (captcha == null) captcha = captchaCheck;
            if (captcha == captchaCheck) return;

            if (StrUtil.isBlank(captcha)) {
                CustomAuthenticationException exception = new CustomAuthenticationException("验证码为空");
                customSimpleUrlAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
                return;
            }
            HttpSession session = request.getSession();
            String captchaCode = String.valueOf(session.getAttribute("captcha"));


            if (StrUtil.isEmpty(captchaCode)) {
                CustomAuthenticationException exception = new CustomAuthenticationException("验证码过期");
                customSimpleUrlAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
                return;
            }

            if (!captcha.equalsIgnoreCase(captchaCode)) {
                CustomAuthenticationException exception = new CustomAuthenticationException("验证码不正确");
                customSimpleUrlAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
                return;
            }
            log.info("验证码正确，用户输入：" + captcha, "session存储：" + captchaCode);
            filterChain.doFilter(request, response);
        }
    }
}
