package top.whgojp.modules.xss.controller.base;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.thymeleaf.util.StringUtils;
import top.whgojp.common.utils.CheckUserInput;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpServletRequest;

@Slf4j
public abstract class XssBaseController {
    @Autowired
    protected CheckUserInput checkUserInput;

    @Autowired
    protected MessageSource messageSource;

    protected R handleXssPayload(String payload, String type, boolean enableFilter) {
        if (StringUtils.isEmpty(payload)) {
            return R.error(msg("xss.reflect.result.emptyPayload"));
        }
        
        log.info("[+]XSS-{}-收到payload：{}", type, payload);
        
        if (enableFilter) {
            String filteredPayload = checkUserInput.filter(payload);
            log.info("[+]XSS-{}-过滤后：{}", type, filteredPayload);
            return R.ok(filteredPayload);
        }
        
        return R.ok(payload);
    }

    protected String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

    protected String getUserAgent(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        return StringUtils.isEmpty(ua) ? "unknown" : ua;
    }

    protected boolean isValidView(String view) {
        return !StringUtils.isEmpty(view) && 
               (view.equals("vul") || view.equals("safe"));
    }
}
