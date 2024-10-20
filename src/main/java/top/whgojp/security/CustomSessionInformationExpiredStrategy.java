package top.whgojp.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.stereotype.Component;
import top.whgojp.common.utils.R;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @description 配置了Session在并发下失效后的处理策略
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/28 10:14
 */

@Component
public class CustomSessionInformationExpiredStrategy implements SessionInformationExpiredStrategy {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
        HttpServletResponse response = event.getResponse();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json;charset=utf-8");

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("status", HttpStatus.UNAUTHORIZED.value());
        responseData.put("error", "Unauthorized");
        responseData.put("message", "您的账号已经在别的地方登录，当前登录已失效。如果密码遭到泄露，请立即修改密码！");
        responseData.put("path", event.getRequest().getRequestURI());

        String json = objectMapper.writeValueAsString(responseData);
        response.getWriter().write(json);
    }

}