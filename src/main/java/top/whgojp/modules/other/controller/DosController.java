package top.whgojp.modules.other.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.ShearCaptcha;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * @description 其他漏洞-Dos攻击
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/10/28 23:04
 */
@Slf4j
@Api(value = "DosController", tags = "其他漏洞-Dos攻击")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/other/dos")
public class DosController {
    @RequestMapping("")
    public String dos() {
        return "vul/other/dos";
    }

    @RequestMapping("/vul")
    public void vul(@RequestParam Integer width, @RequestParam Integer height, HttpServletResponse response) throws IOException {
        response.setContentType("image/jpeg");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache");
        // 验证码参数可控 造成拒绝服务攻击
        ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(width, height,4,3);
        try {
            shearCaptcha.write(response.getOutputStream());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    @RequestMapping("/vul2")
    public String vul2() {

        return "";
    }

}