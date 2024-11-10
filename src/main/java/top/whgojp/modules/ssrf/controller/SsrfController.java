package top.whgojp.modules.ssrf.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.CheckUserInput;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

/**
 * @description SSRF-服务端请求伪造
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/8 10:06
 */
@Slf4j
@Api(value = "SsrfController", tags = "SSRF-服务端请求伪造")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/ssrf")
public class SsrfController {
    @RequestMapping("")
    public String fileUpload() {
        return "vul/ssrf/ssrf";
    }

    @ApiOperation(value = "漏洞环境：服务端请求伪造", notes = "原生漏洞环境，未做任何限制，可调用URLConnection发起任意请求，探测内网服务、读取文件")
    @GetMapping("/vul")
    @ResponseBody
    @ApiImplicitParam(name = "url", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String vul(@ApiParam(name = "url", value = "请求参数", required = true) @RequestParam String url) {
        try {
            URL u = new URL(url);
            URLConnection conn = u.openConnection();    // 这里以URLConnection作为演示
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String content;
            StringBuilder html = new StringBuilder();
            html.append("<pre>");
            while ((content = reader.readLine()) != null) {
                html.append(content).append("\n");
            }
            html.append("</pre>");
            reader.close();
            return html.toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    @Autowired
    private CheckUserInput checkUserInput;

    @ApiOperation(value = "安全代码：请求白名单过滤", notes = "判断协议，对请求URL做白名单过滤")
    @GetMapping("/safe")
    @ResponseBody
    @ApiImplicitParam(name = "url", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String safe(@ApiParam(name = "url", value = "请求参数", required = true) @RequestParam String url) {
        if (!checkUserInput.isHttp(url)) {
            return "检测到不是http(s)协议！";
        } else if (!checkUserInput.ssrfWhiteList(url)) {
            return "非白名单域名！";
        } else {
            try {
                URL u = new URL(url);
                URLConnection conn = u.openConnection();    // 这里以URLConnection作为演示
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String content;
                StringBuilder html = new StringBuilder();
                html.append("<pre>");
                while ((content = reader.readLine()) != null) {
                    html.append(content).append("\n");
                }
                html.append("</pre>");
                reader.close();
                return html.toString();
            } catch (Exception e) {
                return e.getMessage();
            }
        }
    }


}
