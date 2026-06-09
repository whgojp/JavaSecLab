package top.whgojp.modules.logic.idor.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;

/**
 * @description 逻辑漏洞-垂直越权
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/28 22:06
 */
@Slf4j
@Api(value = "VerticalController", tags = "逻辑漏洞-垂直越权")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/logic/idor/vertical")
public class VerticalController {
    private final MessageSource messageSource;

    public VerticalController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String vertical() {
        return "vul/logic/idor/vertical";
    }

    @GetMapping("/vul")
    public String vul() {
        // Vulnerable point: anyone who knows the admin function URL can access it directly, without server-side role validation.
        return "vul/logic/idor/admin";
    }

    @GetMapping("/safe")
    @ResponseBody
    public R safe() {
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        if ("admin".equals(currentUsername)) {
            return R.ok(msg("logic.idor.result.adminAllowed"));
        }
        return R.error(msg("logic.idor.result.adminDenied", currentUsername));
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
