package top.whgojp.modules.xss.controller;

import cn.hutool.core.date.DateUtil;
import io.swagger.annotations.*;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;
import top.whgojp.common.utils.CheckUserInput;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpUtils;

/**
 * @description 跨站脚本-反射型XSS
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/20 16:55
 */
@Slf4j
@Api(value = "ReflectController", tags = "跨站脚本-反射型XSS")
@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/xss/reflect")
public class ReflectController {
    @Autowired
    private CheckUserInput checkUserInput;

    @ApiOperation(value = "漏洞环境：GET型与POST型", notes = "原生漏洞环境,未加任何过滤，Controller接口返回Json类型结果")
    @RequestMapping("/a-vul1-reflect-raw")
    @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public R vul1ReflectRaw(@ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content) {
        log.info("反射型XSS：" + content);
        return R.ok(content);
    }

    @ApiOperation(value = "漏洞环境：String", notes = "原生漏洞环境,未加任何过滤，Controller接口返回String")
    @GetMapping("/a-vul1-reflect-raw-string")
    @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String vul1ReflectRawString(@ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content) {

        return content;
    }

    @SneakyThrows
    @ApiOperation(value = "漏洞环境：Content-Type问题", notes = "Tomcat内置HttpServletResponse，Content-Type导致反射XSS")
    @GetMapping("/a-vul2-reflect-ContentType")
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

    @ApiOperation(value = "安全代码：用户输入验证和过滤", notes = "对用户输入的数据进行验证和过滤，确保不包含恶意代码。使用白名单过滤，只允许特定类型的输入，如纯文本或指定格式的数据")
    @RequestMapping("/a-safe1-CheckUserInput")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "类型", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safe1CheckUserInput(@ApiParam(name = "type", value = "类型", required = true) @RequestParam String type, @ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content, HttpServletResponse response) {
        String filterContent = "";
        switch (type) {
            case "frontEnd":
                filterContent = content; // 前端过滤后传递过来 后端未进行处理
                break;
            case "backEnd":
                filterContent = HtmlUtils.htmlEscape(content);
                log.info("过滤后："+filterContent);
//                filterContent = checkUserInput.checkXssWhiteList(content);
                break;
        }
        return R.ok(filterContent);
    }
    @ApiOperation(value = "安全代码：内容安全策略-CSP防护", notes = "内容安全策略（Content Security Policy）是一种由浏览器实施的安全机制，旨在减少和防范跨站脚本攻击（XSS）等安全威胁。它通过允许网站管理员定义哪些内容来源是可信任的，从而防止恶意内容的加载和执行")
    @RequestMapping("/a-safe2-CSP")
    @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String safe2CSP(@ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content,HttpServletResponse response) {
        response.setHeader("Content-Security-Policy","default-src self");
        response.setHeader("Content-Security-Policy-Report-Only", "default-src 'self'; report-uri /xss/reflect/csp-report-endpoint");
        return content;
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
//            System.out.println("CSP violation report has been written to the file: " + filePath);
//        } catch (IOException e) {
//            System.err.println("Error writing CSP violation report to file: " + e.getMessage());
//        }
    }
    @ApiOperation(value = "安全代码：特殊字符实体转义", notes = "原生漏洞环境,未加任何过滤，Controller接口返回Json类型结果")
    @RequestMapping("/a-safe1-EntityEscape")
    @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String safe2EntityEscape(@ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content) {

        return "";
    }

}
