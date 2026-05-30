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
import top.whgojp.modules.xss.controller.base.XssBaseController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @description 跨站脚本-反射型XSS
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/20 16:55
 */
@Slf4j
@Api(value = "ReflectController", tags = "跨站脚本 - 反射型XSS")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/xss/reflect")
public class ReflectController extends XssBaseController {

    @Autowired
    private CheckUserInput checkUserInput;

    @RequestMapping("/{view}")
    public String reflect(@PathVariable String view) {
        return isValidView(view) ? "vul/xss/reflect/" + view : "error/404";
    }

    @ApiOperation(value = "漏洞场景：GET型与POST型", notes = "原生漏洞场景，未加任何过滤，Controller接口返回JSON类型结果。JSON本身通常不会直接触发XSS，但前端不安全渲染JSON字段时可能触发")
    @RequestMapping("/vul1")
    @ResponseBody
    @ApiImplicitParam(name = "payload", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public R vul1(@ApiParam(name = "payload", value = "请求参数", required = true) @RequestParam String payload) {
        return handleXssPayload(payload, "反射型-GET/POST型", false);
    }

    @ApiOperation(value = "漏洞场景：String", notes = "原生漏洞场景,未加任何过滤，Controller接口返回String")
    @GetMapping("/vul2")
    @ResponseBody
    @ApiImplicitParam(name = "payload", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String vul2(@ApiParam(name = "payload", value = "请求参数", required = true) @RequestParam String payload) {
        log.info("[+]XSS-反射型-String型：" + payload);
        return payload;
    }

    @SneakyThrows
    @ApiOperation(value = "漏洞场景：Content-Type问题", notes = "响应Content-Type决定浏览器解析方式，不可信内容以text/html返回时可能导致反射XSS")
    @GetMapping("/vul3")
    @ResponseBody
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "类型", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "payload", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public void vul3(@ApiParam(name = "type", value = "类型", required = true) @RequestParam String type, @ApiParam(name = "payload", value = "请求参数", required = true) @RequestParam String payload, HttpServletResponse response) {
        switch (type) {
            case "html":
                response.getWriter().print(payload);
                log.info("[+]XSS-反射性-Content-Type：text/html;charset=utf-8：" + payload);
                response.setContentType("text/html;charset=utf-8");
                response.getWriter().flush();
                break;
            case "plain":
                log.info("[+]XSS-反射性-Content-Type：text/plain;charset=utf-8：" + payload);
                response.getWriter().print(payload);
                response.setContentType("text/plain;charset=utf-8");
                response.getWriter().flush();
                break;
            default:
                response.getWriter().print(msg("xss.reflect.result.invalidType"));
                response.setContentType("text/plain;charset=utf-8");
                response.getWriter().flush();
                break;
        }
    }

    private static final String WHITELIST_REGEX = "^[a-zA-Z0-9_\\s]+$";
    private static final Pattern pattern = Pattern.compile(WHITELIST_REGEX);

    @ApiOperation(value = "安全代码：用户输入验证和过滤", notes = "使用白名单限制输入格式，适合约束字段类型；最终仍需根据输出位置进行上下文编码")
    @GetMapping("/safe1")
    @ResponseBody
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "类型", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safe1(@ApiParam(name = "type", value = "类型", required = true) @RequestParam String type, @ApiParam(name = "payload", value = "请求参数", required = true) @RequestParam String payload) {
        String filterContented = "";
        switch (type) {
            case "frontEnd":
                log.info("[-]XSS-反射性-前端白名单过滤：" + payload);
                filterContented = payload; // 前端过滤后传递过来 后端未进行处理(同样存在安全问题)
                break;
            case "backEnd":
                log.info("[-]XSS-反射性-后端白名单过滤：" + payload);
                Matcher matcher = pattern.matcher(payload);
                if (matcher.matches()) {
                    return R.ok(payload);
                } else return R.error(msg("common.illegalInput"));

        }
        return R.ok(filterContented);
    }

    @ApiOperation(value = "安全代码：内容安全策略-CSP防护", notes = "内容安全策略（Content Security Policy）是由浏览器实施的额外防护层，可降低恶意脚本加载和执行风险，但不能替代输出编码与安全模板/DOM用法")
    @GetMapping("/safe2")
    @ResponseBody
    @ApiImplicitParam(name = "payload", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String safe2(@ApiParam(name = "payload", value = "请求参数", required = true) @RequestParam String payload, HttpServletResponse response) {
        response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'");
        response.setHeader("Content-Security-Policy-Report-Only", "default-src 'self'; report-uri /xss/reflect/csp-report-endpoint");
        log.info("[-]XSS-反射性-内容安全策略-CSP防护：" + payload);
        return payload;
    }

    @GetMapping("/a-safe2-CSP-front")
    public String safeCSPFront() {
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

    @ApiOperation(value = "安全代码：HTML正文输出编码", notes = "将HTML正文文本中的特殊字符编码为实体，避免浏览器把不可信数据解析为HTML标签或JavaScript。不同输出上下文需要使用不同编码策略")
    @GetMapping("/safe3")
    @ResponseBody
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "类型", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "payload", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safe3(@ApiParam(name = "type", value = "类型", required = true) @RequestParam String type, @ApiParam(name = "payload", value = "请求参数", required = true) @RequestParam String payload) {
        String filterContented = "";
        switch (type) {
            case "manual":
                payload = StringUtils.replace(payload, "&", "&amp;");
                payload = StringUtils.replace(payload, "<", "&lt;");
                payload = StringUtils.replace(payload, ">", "&gt;");
                payload = StringUtils.replace(payload, "\"", "&quot;");
                payload = StringUtils.replace(payload, "'", "&#x27;");
                payload = StringUtils.replace(payload, "/", "&#x2F;");
                filterContented = payload;
                log.info("[-]XSS-反射型-HTML正文输出编码-手动编码：" + payload);
                break;
            case "spring":
                filterContented = HtmlUtils.htmlEscape(payload);
                log.info("[-]XSS-反射型-HTML正文输出编码-Spring框架：" + payload);
                break;
            default:
                return R.error(msg("xss.reflect.result.invalidParam"));
        }
        return R.ok(filterContented);
    }

    @ApiOperation(value = "安全代码：HttpOnly配置", notes = "HttpOnly可以阻止客户端脚本直接读取带有该属性的Cookie，降低XSS窃取Cookie的影响，但不能修复XSS本身")
    @RequestMapping(value = "/safe4", method = RequestMethod.GET)
    @ResponseBody
    @ApiImplicitParam(name = "payload", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public R safe4(@ApiParam(name = "payload", value = "请求参数", required = true) String payload, HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = request.getCookies()[0];
        cookie.setHttpOnly(true); // 设置为 HttpOnly

        cookie.setMaxAge(600);  // 这里设置生效时间为十分钟
        cookie.setPath("/");

        response.addCookie(cookie);
        return R.ok(msg("xss.reflect.result.httpOnlySet", payload));
    }
}
