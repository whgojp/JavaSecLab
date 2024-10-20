package top.whgojp.modules.xss.controller;

import cn.hutool.core.date.DateUtil;
import io.swagger.annotations.*;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;
import org.thymeleaf.util.StringUtils;
import top.whgojp.common.utils.CheckUserInput;
import top.whgojp.common.utils.R;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpUtils;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @description 跨站脚本-反射型XSS
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/20 16:55
 */
@Slf4j
@Api(value = "ReflectController", tags = "跨站脚本-反射型XSS")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/xss/reflect")
public class ReflectController {
    @Autowired
    private CheckUserInput checkUserInput;
    @RequestMapping("")
    public String xssReflect() {
        return "vul/xss/reflect";
    }
    @RequestMapping("/vul")
    public String xssReflectVul() {
        return "vul/xss/reflect-vul";
    }
    @RequestMapping("/safe")
    public String xssReflectSafe() {
        return "vul/xss/reflect-safe";
    }


    @ApiOperation(value = "漏洞环境：GET型与POST型", notes = "原生漏洞环境,未加任何过滤，Controller接口返回Json类型结果")
    @RequestMapping("/vul1ReflectRaw")
    @ResponseBody
    @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public R vul1ReflectRaw(@ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content) {
        log.info("反射型XSS：" + content);
        return R.ok(content);
    }

    @ApiOperation(value = "漏洞环境：String", notes = "原生漏洞环境,未加任何过滤，Controller接口返回String")
    @GetMapping("/vul1ReflectRawString")
    @ResponseBody
    @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String vul1ReflectRawString(@ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content) {

        return content;
    }

    @SneakyThrows
    @ApiOperation(value = "漏洞环境：Content-Type问题", notes = "Tomcat内置HttpServletResponse，Content-Type导致反射XSS")
    @GetMapping("/vul2ReflectContentType")
    @ResponseBody
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "类型", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public void vul2ReflectContentType(@ApiParam(name = "type", value = "类型", required = true) @RequestParam String type, @ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content, HttpServletResponse response) {
        switch (type) {
            case "html":
                response.getWriter().print(content);
                log.info("反射型XSS，Content-Type：text/html;charset=utf-8：" + content);
                response.setContentType("text/html;charset=utf-8");
                response.getWriter().flush();
                break;
            case "plain":
                log.info("反射型XSS，Content-Type：text/plain;charset=utf-8：" + content);
                response.getWriter().print(content);
                response.setContentType("text/plain;charset=utf-8");    // response默认返回Content-Type类型是text/plain
                response.getWriter().flush();
                break;
            default:
                response.getWriter().print("type字段不存在!");
                response.setContentType("text/plain;charset=utf-8");
                response.getWriter().flush();
                break;
        }
    }
    private static final String WHITELIST_REGEX = "^[a-zA-Z0-9_\\s]+$";
    private static final Pattern pattern = Pattern.compile(WHITELIST_REGEX);

    @ApiOperation(value = "安全代码：用户输入验证和过滤", notes = "对用户输入的数据进行验证和过滤，确保不包含恶意代码。使用白名单过滤，只允许特定类型的输入，如纯文本或指定格式的数据")
    @RequestMapping("/safe1CheckUserInput")
    @ResponseBody
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "类型", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safe1CheckUserInput(@ApiParam(name = "type", value = "类型", required = true) @RequestParam String type, @ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content) {
        String filterContented = "";
        switch (type) {
            case "frontEnd":
                filterContented = content; // 前端过滤后传递过来 后端未进行处理(同样存在安全问题)
                break;
            case "backEnd":
                Matcher matcher = pattern.matcher(content);
                if (matcher.matches()){
                    return R.ok(content);
                }else return R.error("输入内容包含非法字符，请检查输入");

        }
        return R.ok(filterContented);
    }
    @ApiOperation(value = "安全代码：内容安全策略-CSP防护", notes = "内容安全策略（Content Security Policy）是一种由浏览器实施的安全机制，旨在减少和防范跨站脚本攻击（XSS）等安全威胁。它通过允许网站管理员定义哪些内容来源是可信任的，从而防止恶意内容的加载和执行")
    @RequestMapping("/safe2CSP")
    @ResponseBody
    @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String safe2CSP(@ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content,HttpServletResponse response) {
        response.setHeader("Content-Security-Policy","default-src self");
        response.setHeader("Content-Security-Policy-Report-Only", "default-src 'self'; other-uri /xss/reflect/csp-other-endpoint");
        return content;
    }
    @GetMapping("/a-safe2-CSP-front")
    public String safeCSPFront(){
        return "vul/xss/csp-protect";
    }
    @PostMapping("/csp-report-endpoint")
    public void receiveCSPReport(@RequestBody String reportData) {
        // 获取当前时间
        String currentTime = DateUtil.now();

        // 构建报告内容，包括时间和报告详情
        String reportContent = "CSP Violation Report Time: " + currentTime + "\n" +
                "Report Detail:\n" + reportData + "\n\n";

        log.info(reportContent);
        // 写入文件
//        String filePath = "/path/to/your/static/csp_reports.txt";  // 请替换为实际的文件路径
//        try (PrintWriter out = new PrintWriter(new FileWriter(filePath, true))) {
//            out.append(reportContent);
//            System.out.println("CSP violation other has been written to the file: " + filePath);
//        } catch (IOException e) {
//            System.err.println("Error writing CSP violation other to file: " + e.getMessage());
//        }
    }
    @ApiOperation(value = "安全代码：特殊字符实体转义", notes = "特殊字符实体转义是一种将 HTML 中的特殊字符转换为预定义实体表示的过程。这种转义是为了确保在 HTML 页面中正确显示特定字符，同时避免它们被浏览器误解为 HTML 标签或JavaScript代码的一部分，从而导致页面结构混乱或安全漏洞。")
    @RequestMapping("/safe3EntityEscape")
    @ResponseBody
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "类型", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safe3EntityEscape(@ApiParam(name = "type", value = "类型", required = true) @RequestParam String type, @ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content) {
        String filterContented = "";
        switch (type){
            case "manual":
                content = StringUtils.replace(content, "&", "&amp;");
                content = StringUtils.replace(content, "<", "&lt;");
                content = StringUtils.replace(content, ">", "&gt;");
                content = StringUtils.replace(content, "\"", "&quot;");
                content = StringUtils.replace(content, "'", "&#x27;");
                content = StringUtils.replace(content, "/", "&#x2F;");
                filterContented = content;
                break;
            case "spring":
                filterContented = HtmlUtils.htmlEscape(content);
                break;
            default:
                return R.error("参数输入有误！");
        }
        return R.ok(filterContented);
    }

    @ApiOperation(value = "安全代码：HttpOnly配置", notes = "HttpOnly是HTTP响应头属性，用于增强Web应用程序安全性。它防止客户端脚本访问(只能通过http/https协议访问)带有HttpOnly标记的 cookie，从而减少跨站点脚本攻击（XSS）的风险。")
    @RequestMapping(value = "/safe4HttpOnly", method = RequestMethod.GET)
    @ResponseBody
    @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public R safe4HttpOnly(@ApiParam(name = "content", value = "请求参数", required = true) String content, HttpServletRequest request,HttpServletResponse response) {
        Cookie cookie = request.getCookies()[0];
        cookie.setHttpOnly(true); // 设置为 HttpOnly

        cookie.setMaxAge(600);  // 这里设置生效时间为十分钟
        cookie.setPath("/");

        response.addCookie(cookie);
        return R.ok("已设置httponly(有效期10分钟)，请打开控制台查看cookie属性："+content);
    }
}
