package top.whgojp.modules.logic.captcha.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.ShearCaptcha;
import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * @description 逻辑漏洞-验证码安全
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/11/13 22:47
 */
@Slf4j
@Api(value = "GraphicController", tags = "逻辑漏洞-验证码安全")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/logic/captcha/graphic")
public class GraphicController {
    private final MessageSource messageSource;

    public GraphicController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String graphic() {
        return "vul/logic/captcha/graphic";
    }

    // Test account credentials.
    final String REAL_USERNAME = "admin";
    final String REAL_PASSWORD = "admin123";

    @GetMapping("/img")
    public void captcha(HttpSession session, HttpServletResponse response) throws Exception {
        response.setContentType("image/jpeg");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache");

        // Define width, height, captcha length, and interference line width.
        ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(90, 30, 4, 3);
        try {
            // Output the captcha image.
            shearCaptcha.write(response.getOutputStream());
            String captchaCode = shearCaptcha.getCode();
            session.setAttribute("vulCaptcha", captchaCode);
            session.setAttribute("captchaCreationTime", System.currentTimeMillis());
            log.info("session id {}, generated captcha {}", session.getId(), captchaCode);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Boolean verifyCaptcha(String captchaInput, HttpSession session) {
        String sessionCaptcha = (String) session.getAttribute("vulCaptcha");
        Long captchaCreationTime = (Long) session.getAttribute("captchaCreationTime");
        // Return false if captcha or creation time is missing.
        if (sessionCaptcha == null || captchaCreationTime == null) {
//            return false;
            return false;
        }

        // Captcha is valid for 300 seconds (5 minutes).
        long captchaExpiryTime = 300 * 1000;

        // Check whether the captcha has expired.
        if (System.currentTimeMillis() - captchaCreationTime > captchaExpiryTime) {
            session.removeAttribute("vulCaptcha");
            session.removeAttribute("captchaCreationTime");
//            return false;
            return false;
        }

        // Validate the submitted captcha.
        if (sessionCaptcha.equalsIgnoreCase(captchaInput)) {
            // Vulnerable demo: captcha is not cleared after successful validation.
//            session.removeAttribute("vulCaptcha");
//            session.removeAttribute("captchaCreationTime");
//            return true;
            return true;
        } else {
//            return false;
            return false;
        }

    }

    @PostMapping("/vul1")
    @ResponseBody
    public R vul1(String username, String password, String captcha, HttpSession session) {
        if (verifyCaptcha(captcha, session)) {
            log.info("captcha is valid");
            if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {
                return R.ok(msg("logic.captcha.result.bruteForceSuccess", username, password));
            } else {
                return R.error(msg("logic.captcha.result.accountInvalid"));
            }
        } else {
            log.info("captcha is invalid, valid for 5 minutes");
            return R.error(msg("logic.captcha.result.captchaInvalidFive"));
        }
    }

    @PostMapping("/vul2")
    @ResponseBody
    public R vul2(String username, String password, String captcha, HttpSession session) {
        String sessionCaptcha = (String) session.getAttribute("vulCaptcha");
        // Universal captcha: 6666.
        if ("6666".equals(captcha) || (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha))) {
            // Clear the old captcha.
            session.removeAttribute("vulCaptcha");
            if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {
                return R.ok(msg("logic.captcha.result.bruteForceSuccess", username, password));
            } else return R.error(msg("logic.captcha.result.accountInvalid"));
        } else {
            session.removeAttribute("vulCaptcha");
            return R.error(msg("logic.captcha.result.captchaInvalid"));
        }
    }

    @PostMapping("/vul3")
    @ResponseBody
    public R vul3(String username, String password, String captcha, HttpSession session) {
        String sessionCaptcha = (String) session.getAttribute("vulCaptcha");
        if (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha)) {
            session.removeAttribute("vulCaptcha");
            if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {
                return R.ok(msg("logic.captcha.result.bruteForceSuccess", username, password));
            } else return R.error(msg("logic.captcha.result.accountInvalid"));
        } else {
            session.removeAttribute("vulCaptcha");
            return R.error(msg("logic.captcha.result.captchaInvalid"));
        }
    }
    @GetMapping("/safeImg")
    public void safeImg(HttpSession session, HttpServletResponse response) throws Exception {
        response.setContentType("image/jpeg");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache");

        // Define width, height, captcha length, and interference line width.
        ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(90, 30, 6, 3);
        try {
            // Output the captcha image.
            shearCaptcha.write(response.getOutputStream());
            String captchaCode = shearCaptcha.getCode();
            session.setAttribute("safeCaptcha", captchaCode);
            session.setAttribute("captchaTimestamp", System.currentTimeMillis());
            log.info("session id {}, generated captcha {}", session.getId(), captchaCode);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    @PostMapping("/safe")
    @ResponseBody
    public R safe(String username, String password, String captcha, HttpSession session) {
        String sessionCaptcha = (String) session.getAttribute("safeCaptcha");
        Long captchaTimestamp = (Long) session.getAttribute("captchaTimestamp");
        // Check whether the captcha has expired (1-minute lifetime).
        if (captchaTimestamp == null || System.currentTimeMillis() - captchaTimestamp > 60 * 1000) {
            session.removeAttribute("safeCaptcha");
            session.removeAttribute("captchaTimestamp");
            return R.error(msg("logic.captcha.result.captchaExpired"));
        }
        // Validate captcha.
        if (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha)) {
            session.removeAttribute("safeCaptcha");
            session.removeAttribute("captchaTimestamp");
            // Validate account credentials.
            if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {
                return R.ok(msg("logic.captcha.result.loginSuccess", username, password));
            } else {
                return R.error(msg("logic.captcha.result.accountInvalid"));
            }
        } else {
            session.removeAttribute("safeCaptcha");
            session.removeAttribute("captchaTimestamp");
            return R.error(msg("logic.captcha.result.captchaRetry"));
        }
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
