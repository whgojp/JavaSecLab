package top.whgojp.modules.other.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import top.whgojp.common.utils.CheckUserInput;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

/**
 * @description 其他漏洞-URL重定向
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/10 18:05
 */
@Slf4j
@Api(value = "URLRedirectController", tags = "其他漏洞-URL重定向")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/other/URLRedirect")
public class UrlRedirectController {
    @RequestMapping("/vul")
    public String UrlRedirectVul() {
        return "vul/other/url-redirect-vul";
    }
    @RequestMapping("/safe")
    public String UrlRedirectSafe() {
        return "vul/other/url-redirect-safe";
    }

    // 基于Spring MVC的重定向方式
    @ApiOperation(value = "漏洞环境：基于Spring MVC的重定向方式", notes = "Spring MVC应用中常见的重定向方式")
    @GetMapping("/vul1")
    public String vul1(@RequestParam("url") String url) {
        return "redirect:" + url;   // Spring MVC写法 302临时重定向
    }

    @ApiOperation(value = "漏洞环境：基于Spring MVC的重定向方式", notes = "使用ModelAndView实现的Spring MVC重定向方式")
    @RequestMapping("/vul2")
    public ModelAndView vul2(@RequestParam("url") String url) {
        return new ModelAndView("redirect:" + url); // Spring MVC写法 使用ModelAndView 302临时重定向
    }

    // 基于Servlet标准的重定向方式
    @ApiOperation(value = "漏洞环境：基于Servlet标准的重定向方式", notes = "基于Servlet标准的重定向方式")
    @RequestMapping("/vul3")
    @ResponseBody
    public static void vul3(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301永久重定向
        response.setHeader("Location", url);
    }

    @ApiOperation(value = "漏洞环境：基于Servlet标准的重定向方式", notes = "基于Servlet标准的重定向方式")
    @RequestMapping("/vul4")
    @ResponseBody
    public static void vul4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        response.sendRedirect(url); // 302临时重定向
    }

    // 基于Spring注解和状态码的重定向方式
    @ApiOperation(value = "漏洞环境：基于Spring注解和状态码的重定向方式", notes = "使用ResponseEntity设置状态码实现重定向")
    @RequestMapping("/vul5")
    @ResponseBody
    public ResponseEntity<Void> vul5(@RequestParam("url") String url) {
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(url));
        return new ResponseEntity<>(headers, HttpStatus.FOUND); // 302临时重定向
    }

    @ApiOperation(value = "漏洞环境：基于Spring注解和状态码的重定向方式", notes = "通过注解设置状态码实现重定向")
    @GetMapping("/vul6")
    @ResponseStatus(HttpStatus.FOUND) // 302临时重定向
    public void vul6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        response.setHeader("Location", url);
    }

    @RequestMapping("/safe1")
    @ResponseBody
    public static void safe1(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        request.setAttribute("message", "正在进行内部转发，请稍候...");

        RequestDispatcher rd = request.getRequestDispatcher(url);
        try {
            rd.forward(request, response);
            log.info("做了内部转发……");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Autowired
    private CheckUserInput checkUserInput;

    @RequestMapping("/safe2")
    @ResponseBody
    public void safe2(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String url = request.getParameter("url");
        if (checkUserInput.checkURL(url)) { // 校验通过
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("  Forbidden: url not in WhiteUrlList!");
            return;
        }
        response.sendRedirect(url);
    }



}


