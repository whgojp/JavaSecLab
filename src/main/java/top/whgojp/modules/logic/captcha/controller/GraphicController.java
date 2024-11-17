package top.whgojp.modules.logic.captcha.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.ShearCaptcha;
import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
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

    @RequestMapping("")
    public String graphic() {
        return "vul/logic/captcha/graphic";
    }

    // 测试账号密码
    final String REAL_USERNAME = "admin";
    final String REAL_PASSWORD = "admin123";

    @GetMapping("/img")
    public void captcha(HttpSession session, HttpServletResponse response) throws Exception {
        response.setContentType("image/jpeg");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache");

        //定义图形验证码的长、宽、验证码字符数、干扰线宽度
        ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(90, 30, 4, 3);
        try {
            //输出
            shearCaptcha.write(response.getOutputStream());
            String captchaCode = shearCaptcha.getCode();
            session.setAttribute("vulCaptcha", captchaCode);
            session.setAttribute("captchaCreationTime", System.currentTimeMillis());
            log.info("session id {}， 生成的验证码 {}", session.getId(), captchaCode);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Boolean verifyCaptcha(String captchaInput, HttpSession session) {
        String sessionCaptcha = (String) session.getAttribute("vulCaptcha");
        Long captchaCreationTime = (Long) session.getAttribute("captchaCreationTime");
        // 如果没有验证码或生成时间，返回失败
        if (sessionCaptcha == null || captchaCreationTime == null) {
//            return R.error("验证码已失效，请刷新后重试");
            return false;
        }

        // 验证码有效期为300秒（5分钟）
        long captchaExpiryTime = 300 * 1000; // 300秒转换为毫秒

        // 检查验证码是否过期
        if (System.currentTimeMillis() - captchaCreationTime > captchaExpiryTime) {
            session.removeAttribute("vulCaptcha");
            session.removeAttribute("captchaCreationTime");
//            return R.error("验证码已过期，请刷新后重试");
            return false;
        }

        // 验证输入的验证码
        if (sessionCaptcha.equalsIgnoreCase(captchaInput)) {
            // 验证成功后清除 session 中的验证码
//            session.removeAttribute("vulCaptcha");
//            session.removeAttribute("captchaCreationTime");
//            return R.ok("验证码验证成功");
            return true;
        } else {
//            return R.ok("验证码错误，请重新输入");
            return false;
        }

    }

    @PostMapping("/vul1")
    @ResponseBody
    public R vul1(String username, String password, String captcha, HttpSession session) {
        if (verifyCaptcha(captcha, session)) {
            log.info("验证码有效，校验成功");
            if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {
                return R.ok("账号爆破成功！用户名：" + username + ",密码：" + password);
            } else {
                return R.error("账号或密码错误!");
            }
        } else {
            log.info("验证码错误！(5分钟内有效)");
            return R.error("验证码错误！(5分钟内有效)");
        }
    }

    @PostMapping("/vul2")
    @ResponseBody
    public R vul2(String username, String password, String captcha, HttpSession session) {
        String sessionCaptcha = (String) session.getAttribute("vulCaptcha");
        // 万能验证码：6666
        if ("6666".equals(captcha) || (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha))) {
            // 及时清除旧验证码
            session.removeAttribute("vulCaptcha");
            if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {
                return R.ok("账号爆破成功！用户名：" + username + ",密码：" + password);
            } else return R.error("账号或密码错误!");
        } else {
            session.removeAttribute("vulCaptcha");
            return R.error("验证码错误！");
        }
    }

    @PostMapping("/vul3")
    @ResponseBody
    public R vul3(String username, String password, String captcha, HttpSession session) {
        String sessionCaptcha = (String) session.getAttribute("vulCaptcha");
        if (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha)) {
            session.removeAttribute("vulCaptcha");
            if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {
                return R.ok("账号爆破成功！用户名：" + username + ",密码：" + password);
            } else return R.error("账号或密码错误!");
        } else {
            session.removeAttribute("vulCaptcha");
            return R.error("验证码错误！");
        }
    }
    @GetMapping("/safeImg")
    public void safeImg(HttpSession session, HttpServletResponse response) throws Exception {
        response.setContentType("image/jpeg");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache");

        //定义图形验证码的长、宽、验证码字符数、干扰线宽度
        ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(90, 30, 6, 3);
        try {
            //输出
            shearCaptcha.write(response.getOutputStream());
            String captchaCode = shearCaptcha.getCode();
            session.setAttribute("safeCaptcha", captchaCode);
            session.setAttribute("captchaTimestamp", System.currentTimeMillis());
            log.info("session id {}， 生成的验证码 {}", session.getId(), captchaCode);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    @PostMapping("/safe")
    @ResponseBody
    public R safe(String username, String password, String captcha, HttpSession session) {
        String sessionCaptcha = (String) session.getAttribute("safeCaptcha");
        Long captchaTimestamp = (Long) session.getAttribute("captchaCreationTime");
        // 验证验证码是否已失效（1分钟有效）
        if (captchaTimestamp == null || System.currentTimeMillis() - captchaTimestamp > 60 * 1000) {
            session.removeAttribute("safeCaptcha");
            session.removeAttribute("captchaTimestamp");
            return R.error("验证码已失效，请重新获取！");
        }
        // 校验验证码
        if (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha)) {
            session.removeAttribute("safeCaptcha");
            session.removeAttribute("captchaTimestamp");
            // 校验账号密码
            if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {
                return R.ok("登录成功！用户名：" + username + ",密码：" + password);
            } else {
                return R.error("账号或密码错误!");
            }
        } else {
            session.removeAttribute("safeCaptcha");
            session.removeAttribute("captchaTimestamp");
            return R.error("验证码错误，请重新输入！");
        }
    }


}
