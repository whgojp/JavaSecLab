package top.whgojp.modules.ssrf.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.CheckUserInput;

import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;

/**
 * @description SSRF - server-side request forgery
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/8 10:06
 */
@Slf4j
@Api(value = "SsrfController", tags = "SSRF - Server-Side Request Forgery")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/ssrf")
public class SsrfController {
    @Autowired
    private MessageSource messageSource;

    @RequestMapping("")
    public String fileUpload() {
        return "vul/ssrf/ssrf";
    }

    @ApiOperation(value = "Simulated internal metadata service", notes = "Used by the SSRF demo to simulate server-side access to internal or cloud metadata APIs")
    @GetMapping("/internal/metadata")
    @ResponseBody
    public String internalMetadata() {
        return "instance-id: i-javaseclab-ssrf\n"
                + "role: internal-admin\n"
                + "token: javaseclab-metadata-token\n"
                + "source: 127.0.0.1";
    }

    @ApiOperation(value = "Simulated redirect chain", notes = "Demonstrates why SSRF defenses must disable automatic redirects or revalidate every hop")
    @GetMapping("/redirect")
    public void redirect(@RequestParam String target, HttpServletResponse response) throws IOException {
        response.sendRedirect(target);
    }

    @ApiOperation(value = "Vulnerable scenario: server-side request forgery", notes = "Native vulnerable scenario without restrictions; URLConnection can initiate arbitrary requests, probe internal services, or read files")
    @GetMapping("/vul")
    @ResponseBody
    @ApiImplicitParam(name = "url", value = "Request parameter", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String vul(@ApiParam(name = "url", value = "Request parameter", required = true) @RequestParam String url) {
        try {
            URL u = new URL(url);
            URLConnection conn = u.openConnection();    // URLConnection is used for this demo.
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

    @ApiOperation(value = "Safe code: request allowlist filtering", notes = "Validate the protocol and apply an allowlist to the request URL")
    @GetMapping("/safe")
    @ResponseBody
    @ApiImplicitParam(name = "url", value = "Request parameter", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public String safe(@ApiParam(name = "url", value = "Request parameter", required = true) @RequestParam String url) {
        if (!checkUserInput.isHttp(url)) {
            return msg("ssrf.result.invalidProtocol");
        } else if (!checkUserInput.ssrfWhiteList(url)) {
            return msg("ssrf.result.notAllowlisted");
        } else {
            try {
                URL u = new URL(url);
                HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                conn.setInstanceFollowRedirects(false);
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
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

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
