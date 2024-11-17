package top.whgojp.modules.logic.captcha.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
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
    @RequestMapping("")
    public String sms() {
        return "vul/logic/captcha/sms";
    }

    @GetMapping("/code")
    @ResponseBody
    public R code(String phone, HttpSession session) {
        if (phone == null || phone.isEmpty() || !phone.matches("^1[3-9]\\d{9}$")) {
            return R.error("手机号格式不正确！");
        }

        Random random = new Random();
        // 随机生成6位数验证码
        String captcha = String.valueOf(100000 + random.nextInt(900000));
        session.setAttribute("phone", phone);
        session.setAttribute("smsCode", captcha);
        session.setAttribute("captchaTimestamp", System.currentTimeMillis());

        System.out.println("发送短信验证码：" + captcha + " 给手机号：" + phone);

        return R.ok("发送验证码成功！" + captcha);
    }

    @RequestMapping("/vul1")
    @ResponseBody
    public R vul1(String phone, String code, HttpSession session) {
        if (phone == null || phone.isEmpty()) {
            return R.error("手机号不能为空！");
        }
        String sessionPhone = (String) session.getAttribute("phone");
        String sessionCaptcha = (String) session.getAttribute("smsCode");
        Long captchaTimestamp = (Long) session.getAttribute("captchaTimestamp");
        if (sessionPhone == null || sessionCaptcha == null || captchaTimestamp == null) {
            return R.error("验证码已失效，请重新获取！");
        }
        if (!sessionPhone.equals(phone)) {
            return R.error("手机号与验证码不匹配！");
        }
        if (System.currentTimeMillis() - captchaTimestamp > 5 * 60 * 1000) {
            session.removeAttribute("phone");
            session.removeAttribute("smsCode");
            session.removeAttribute("captchaTimestamp");
            return R.error("验证码已过期，请重新获取！");
        }
        if (!sessionCaptcha.equals(code)) {
            return R.error("验证码错误，请重新输入！");
        }
        session.removeAttribute("phone");
        session.removeAttribute("smsCode");
        session.removeAttribute("captchaTimestamp");
        return R.ok("验证通过！用户："+phone);
    }

    @GetMapping("/code2")
    @ResponseBody
    public R code2(String phone, HttpSession session) {
        if (phone == null || phone.isEmpty() || !phone.matches("^1[3-9]\\d{9}$")) {
            return R.error("手机号格式不正确！");
        }

        Random random = new Random();
        String captcha = String.valueOf(100000 + random.nextInt(900000));
        session.setAttribute("phone", phone);
        session.setAttribute("smsCode", captcha);
        session.setAttribute("captchaTimestamp", System.currentTimeMillis());

        System.out.println("发送短信验证码：" + captcha + " 给手机号：" + phone);

        return R.ok("发送验证码成功！");
    }
    @RequestMapping("/vul2")
    @ResponseBody
    public R vul2(String phone, String code, @RequestParam(required = false, defaultValue = "false") boolean code_verify, HttpSession session) {
        if (phone == null || phone.isEmpty()) {
            return R.error("手机号不能为空！");
        }
        String sessionPhone = (String) session.getAttribute("phone");
        String sessionCaptcha = (String) session.getAttribute("smsCode");
        Long captchaTimestamp = (Long) session.getAttribute("captchaTimestamp");
        if (sessionPhone == null || sessionCaptcha == null || captchaTimestamp == null) {
            return R.error("验证码已失效，请重新获取！");
        }
        if (!sessionPhone.equals(phone)) {
            return R.error("手机号与验证码不匹配！");
        }
        if (System.currentTimeMillis() - captchaTimestamp > 5 * 60 * 1000) {
            session.removeAttribute("phone");
            session.removeAttribute("smsCode");
            session.removeAttribute("captchaTimestamp");
            return R.error("验证码已过期，请重新获取！");
        }
        if (code_verify){
            return R.ok("验证通过！用户："+phone);
        }
        if (!sessionCaptcha.equals(code)) {
            return R.error("验证码错误，请重新输入！");
        }
        session.removeAttribute("phone");
        session.removeAttribute("smsCode");
        session.removeAttribute("captchaTimestamp");
        return R.ok("验证通过！用户："+phone);
    }
}
