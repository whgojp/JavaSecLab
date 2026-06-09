package top.whgojp.modules.logic.captcha.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpSession;
import java.util.Random;

/**
 * @description 逻辑漏洞-验证码安全
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/11/13 22:47
 */
@Slf4j
@Api(value = "SMSController", tags = "逻辑漏洞-验证码安全")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/logic/captcha/sms")
public class SMSController {
    private final MessageSource messageSource;

    public SMSController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String sms() {
        return "vul/logic/captcha/sms";
    }

    @GetMapping("/code")
    @ResponseBody
    public R code(String phone, HttpSession session) {
        if (phone == null || phone.isEmpty() || !phone.matches("^1[3-9]\\d{9}$")) {
            return R.error(msg("logic.captcha.result.phoneInvalid"));
        }

        Random random = new Random();
        // Randomly generate a 6-digit captcha.
        String captcha = String.valueOf(100000 + random.nextInt(900000));
        session.setAttribute("phone", phone);
        session.setAttribute("smsCode", captcha);
        session.setAttribute("captchaTimestamp", System.currentTimeMillis());

        log.info("send SMS captcha {} to phone {}", captcha, phone);

        return R.ok(msg("logic.captcha.result.smsSentEcho", captcha));
    }

    @RequestMapping("/vul1")
    @ResponseBody
    public R vul1(String phone, String code, HttpSession session) {
        if (phone == null || phone.isEmpty()) {
            return R.error(msg("logic.captcha.result.phoneRequired"));
        }
        String sessionPhone = (String) session.getAttribute("phone");
        String sessionCaptcha = (String) session.getAttribute("smsCode");
        Long captchaTimestamp = (Long) session.getAttribute("captchaTimestamp");
        if (sessionPhone == null || sessionCaptcha == null || captchaTimestamp == null) {
            return R.error(msg("logic.captcha.result.smsExpired"));
        }
        if (!sessionPhone.equals(phone)) {
            return R.error(msg("logic.captcha.result.phoneMismatch"));
        }
        if (System.currentTimeMillis() - captchaTimestamp > 5 * 60 * 1000) {
            session.removeAttribute("phone");
            session.removeAttribute("smsCode");
            session.removeAttribute("captchaTimestamp");
            return R.error(msg("logic.captcha.result.smsTimeout"));
        }
        if (!sessionCaptcha.equals(code)) {
            return R.error(msg("logic.captcha.result.smsWrong"));
        }
        session.removeAttribute("phone");
        session.removeAttribute("smsCode");
        session.removeAttribute("captchaTimestamp");
        return R.ok(msg("logic.captcha.result.smsVerified", phone));
    }

    @GetMapping("/code2")
    @ResponseBody
    public R code2(String phone, HttpSession session) {
        if (phone == null || phone.isEmpty() || !phone.matches("^1[3-9]\\d{9}$")) {
            return R.error(msg("logic.captcha.result.phoneInvalid"));
        }

        Random random = new Random();
        String captcha = String.valueOf(100000 + random.nextInt(900000));
        session.setAttribute("phone", phone);
        session.setAttribute("smsCode", captcha);
        session.setAttribute("captchaTimestamp", System.currentTimeMillis());

        log.info("send SMS captcha {} to phone {}", captcha, phone);

        return R.ok(msg("logic.captcha.result.smsSent"));
    }
    @RequestMapping("/vul2")
    @ResponseBody
    public R vul2(String phone, String code, @RequestParam(required = false, defaultValue = "false") boolean code_verify, HttpSession session) {
        if (phone == null || phone.isEmpty()) {
            return R.error(msg("logic.captcha.result.phoneRequired"));
        }
        String sessionPhone = (String) session.getAttribute("phone");
        String sessionCaptcha = (String) session.getAttribute("smsCode");
        Long captchaTimestamp = (Long) session.getAttribute("captchaTimestamp");
        if (sessionPhone == null || sessionCaptcha == null || captchaTimestamp == null) {
            return R.error(msg("logic.captcha.result.smsExpired"));
        }
        if (!sessionPhone.equals(phone)) {
            return R.error(msg("logic.captcha.result.phoneMismatch"));
        }
        if (System.currentTimeMillis() - captchaTimestamp > 5 * 60 * 1000) {
            session.removeAttribute("phone");
            session.removeAttribute("smsCode");
            session.removeAttribute("captchaTimestamp");
            return R.error(msg("logic.captcha.result.smsTimeout"));
        }
        if (code_verify){
            return R.ok(msg("logic.captcha.result.smsVerified", phone));
        }
        if (!sessionCaptcha.equals(code)) {
            return R.error(msg("logic.captcha.result.smsWrong"));
        }
        session.removeAttribute("phone");
        session.removeAttribute("smsCode");
        session.removeAttribute("captchaTimestamp");
        return R.ok(msg("logic.captcha.result.smsVerified", phone));
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }
}
