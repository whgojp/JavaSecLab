package top.whgojp.modules.crossorigin.controller;

import io.jsonwebtoken.io.IOException;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @description 跨源安全问题
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/6 20:46
 */
@Slf4j
@Api(value = "CrossOriginController", tags = "跨域安全问题")
@Controller
//@CrossOrigin(origins = "*")
@RequestMapping("/crossorigin")
public class CrossOriginController {

    @RequestMapping("/cors")
    public String cors() {
        return "vul/crossorigin/cors";
    }
    @RequestMapping("/jsonp")
    public String jsonp() {
        return "vul/crossorigin/jsonp";
    }

    @GetMapping("/corsVul")
    @ResponseBody
    public R corsVul(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("origin");

        if (origin != null) {
            response.setHeader("Access-Control-Allow-Origin", origin);
        } else {
            response.setHeader("Access-Control-Allow-Origin", "http://example.com");
        }

        // 允许携带 Cookie 或其他凭证
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

        return R.ok("CORS漏洞演示：username:admin,password:Admin123");
    }
    @CrossOrigin(origins = {"http://127.0.0.1:8080", "https://127.0.0.1:8080"}, allowCredentials = "true")
    @GetMapping("/corsSafe")
    @ResponseBody
    public R corsSafe(HttpServletRequest request, HttpServletResponse response) {
        // 记录安全 CORS 请求来源
        String origin = request.getHeader("origin");
        // 允许携带凭证，但前提是 `Access-Control-Allow-Origin` 与可信来源匹配
        response.setHeader("Access-Control-Allow-Credentials", "true");

        return R.ok("配置CORS可信源白名单");
    }

    @GetMapping("/jsonpVul")
    public void jsonpVul(HttpServletRequest request, HttpServletResponse response) throws IOException, java.io.IOException {
        String callback = request.getParameter("callback");
        String sensitiveData = "{\"username\":\"admin\",\"password\":\"Admin123\"}";

        // 返回数据包装成 JSONP 格式，并没有对 callback 参数进行安全验证
        String jsonpResponse = callback + "(" + sensitiveData + ");";

        // 设置响应类型为 JavaScript 脚本
        response.setContentType("application/javascript");
        response.getWriter().write(jsonpResponse);
    }


    @GetMapping("/jsonpSafe")
    public void jsonpSafe(HttpServletRequest request, HttpServletResponse response) throws IOException, java.io.IOException {
        String callback = request.getParameter("callback");

        // 校验回调函数名是否合法
        if (callback == null || !callback.matches("^[a-zA-Z_$][a-zA-Z0-9_$]*$")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid callback");
            return;
        }

        String sensitiveData = "{\"username\":\"admin\",\"password\":\"Admin123\"}";
        response.setContentType("application/javascript");
        response.getWriter().write(callback + "(" + sensitiveData + ");");
    }


}
