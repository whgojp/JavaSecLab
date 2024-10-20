package top.whgojp.modules.other.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;

/**
 * @description 其他漏洞-XFF伪造
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/12 21:45
 */
@Slf4j
@Api(value = "XffForgeryController", tags = "其他漏洞-XFF伪造")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/other/xff")
public class XffForgeryController {
    @ApiOperation("")
    @RequestMapping("")
    public String XffForgery() {
        return "vul/other/xff-forgery";
    }

    @RequestMapping("/ip")
    @ResponseBody
    public String getIp(HttpServletRequest request) {
        final String remoteHost = request.getRemoteHost();
        log.info("获取到的IP：" + remoteHost);
        return "获取到的IP：" + remoteHost;
    }

    @RequestMapping("/buffli")
    public String buffli(HttpServletRequest request, Model model) {
        // 前后端不分离 使用request.getRemoteAddr()获取客户端IP
        final String remoteHost = request.getRemoteAddr();
        boolean isClientIP8888 = "8.8.8.8".equals(remoteHost);
        model.addAttribute("clientIP", remoteHost);

        // 添加敏感信息
        if (isClientIP8888) {
            model.addAttribute("sensitiveInfo", "username:admin,password:Admin123");
        }
        return "vul/other/onlyForGoogle";
    }

    @RequestMapping("/onlyForGoogle")
    public String onlyForGoogle(HttpServletRequest request, HttpServletResponse response, Model model, String xff) {
        String remoteHost = request.getHeader("X-Forwarded-For");
        model.addAttribute("clientIP", remoteHost);

        return "vul/other/onlyForGoogle";
    }

    @RequestMapping("/ffli")
    public String ffli(HttpServletRequest request, HttpServletResponse response, Model model, String xff) {

        // 前后端分离 模拟通过X-Forwarded-For头获取客户端IP
        String remoteHost = "";
        if (xff.equals("true")) {
            remoteHost = request.getHeader("X-Forwarded-For");
        }
        if (remoteHost.isEmpty()) {
            remoteHost = request.getRemoteHost();
        }
        boolean isClientIP8888 = "8.8.8.8".equals(remoteHost);
        // 添加敏感信息
        model.addAttribute("clientIP", remoteHost);
        if (isClientIP8888) {
            model.addAttribute("sensitiveInfo", "username:admin,password:Admin123");
        }

        return "vul/other/onlyForGoogle";
    }

    @RequestMapping("/safe")
    public String safe(HttpServletRequest request, HttpServletResponse response, Model model, String xff){
        String remoteHost = "";
        if (xff.equals("true")) {
            remoteHost = request.getHeader("X-Forwarded-For");
        }
        if (remoteHost.isEmpty()) {
            remoteHost = request.getRemoteHost();
        }
        if (!isTrustedProxy(remoteHost)){
            model.addAttribute("clientIP", request.getRemoteAddr());
            model.addAttribute("sensitiveInfo", "源ip不在白名单范围内！");
            return "vul/other/onlyForGoogle";
        }
        boolean isClientIP8888 = "8.8.8.8".equals(remoteHost);
        model.addAttribute("clientIP", remoteHost);
        if (isClientIP8888) {
            model.addAttribute("sensitiveInfo", "username:admin,password:Admin123");
        }
        return "vul/other/onlyForGoogle";
    }
    // 判断是否来自可信代理
    private boolean isTrustedProxy(String ip) {
        return Arrays.asList("127.0.0.1", "192.168.1.1", "10.0.0.1").contains(ip);
    }


}
