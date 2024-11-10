package top.whgojp.modules.infoleak.controller;

import io.swagger.annotations.Api;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.constant.SysConstant;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * @description 敏感信息泄漏-目录遍历
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/18 09:33
 */
@Slf4j
@Api(value = "DirTraversalController", tags = "敏感信息泄漏-目录遍历")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/infoLeak/dirTraversal")
public class DirTraversalController {

    @Autowired
    private SysConstant sysConstant;

    @RequestMapping("")
    public String DirTraversal() {
        return "vul/infoleak/dirTraversal";
    }

    @GetMapping("/vul")
    @ResponseBody
    public String vul(@RequestParam String dir) {
        String staticFolderPath = sysConstant.getStaticFolder();
        File baseDir = new File(staticFolderPath);
        File requestedDir = new File(baseDir, dir);

        // 生成HTML输出
        StringBuilder response = new StringBuilder();
        response.append("<!DOCTYPE HTML>");
        response.append("<html lang=\"en\">");
        response.append("<head>");
        response.append("<meta charset=\"utf-8\">");
        response.append("<title>Directory listing for ").append(dir).append("</title>");
        response.append("<script>");
        response.append("function addBaseUrl(url) {");
        response.append("  const baseUrl = window.location.origin;");
        response.append("  return baseUrl + url;");
        response.append("}");
        response.append("</script>");
        response.append("</head>");
        response.append("<body>");
        response.append("<h1>Directory listing for ").append(dir).append("</h1>");
        response.append("<hr>");
        response.append("<ul>");

        File[] files = requestedDir.listFiles();
        if (files != null) {
            for (File file : files) {
                response.append("<li>");
                if (file.isDirectory()) {
                    response.append("<a href=\"?dir=").append(dir);
                    if (!dir.endsWith("/")) {
                        response.append("/");
                    }
                    response.append(file.getName()).append("/\">").append(file.getName()).append("/</a>");
                } else {
                    response.append("<a href=\"javascript:void(0);\" onclick=\"window.location.href=addBaseUrl('").append(dir);
                    if (!dir.endsWith("/")) {
                        response.append("/");
                    }
                    response.append(file.getName()).append("');\">").append(file.getName()).append("</a>");
                }
                response.append("</li>");
            }
        } else {
            response.append("Failed to list contents of the directory.");
        }

        response.append("</ul>");
        response.append("<hr>");
        response.append("</body>");
        response.append("</html>");
        return response.toString();
    }

    @GetMapping("/safe1")
    @ResponseBody
    @SneakyThrows
    public String safe1(@RequestParam String dir) {
        String staticFolderPath = sysConstant.getStaticFolder();
        File baseDir = new File(staticFolderPath);

        String decodedDir = URLDecoder.decode(dir, StandardCharsets.UTF_8.name());

        // 进行敏感字符过滤，禁止使用 '.'、';'、'\' 和 '%'
        if (decodedDir.contains(".") || decodedDir.contains(";") || decodedDir.contains("\\") || decodedDir.contains("%")) {
            return "非法字符！";
        }
        File requestedDir = new File(baseDir, dir);


        // 生成HTML输出
        StringBuilder response = new StringBuilder();
        response.append("<!DOCTYPE HTML>");
        response.append("<html lang=\"en\">");
        response.append("<head>");
        response.append("<meta charset=\"utf-8\">");
        response.append("<title>Directory listing for ").append(dir).append("</title>");
        response.append("<script>");
        response.append("function addBaseUrl(url) {");
        response.append("  const baseUrl = window.location.origin;");
        response.append("  return baseUrl + url;");
        response.append("}");
        response.append("</script>");
        response.append("</head>");
        response.append("<body>");
        response.append("<h1>Directory listing for ").append(dir).append("</h1>");
        response.append("<hr>");
        response.append("<ul>");

        File[] files = requestedDir.listFiles();
        if (files != null) {
            for (File file : files) {
                response.append("<li>");
                if (file.isDirectory()) {
                    response.append("<a href=\"?dir=").append(dir);
                    if (!dir.endsWith("/")) {
                        response.append("/");
                    }
                    response.append(file.getName()).append("/\">").append(file.getName()).append("/</a>");
                } else {
                    response.append("<a href=\"javascript:void(0);\" onclick=\"window.location.href=addBaseUrl('").append(dir);
                    if (!dir.endsWith("/")) {
                        response.append("/");
                    }
                    response.append(file.getName()).append("');\">").append(file.getName()).append("</a>");
                }
                response.append("</li>");
            }
        } else {
            response.append("Failed to list contents of the directory.");
        }

        response.append("</ul>");
        response.append("<hr>");
        response.append("</body>");
        response.append("</html>");
        return response.toString();
    }
    @GetMapping("/safe2")
    @ResponseBody
    public String safe2(@RequestParam String dir) {
        String staticFolderPath = sysConstant.getStaticFolder();
        File baseDir = new File(staticFolderPath);
        File requestedDir = new File(baseDir, dir);

        // 检查请求的目录是否在规定目录内
        try {
            if (!requestedDir.getCanonicalPath().startsWith(baseDir.getCanonicalPath()) || !requestedDir.isDirectory()) {
                return "Directory not found or access denied.";
            }
        } catch (IOException e) {
            return "Error resolving directory path.";
        }

        // 生成HTML输出
        StringBuilder response = new StringBuilder();
        response.append("<!DOCTYPE HTML>");
        response.append("<html lang=\"en\">");
        response.append("<head>");
        response.append("<meta charset=\"utf-8\">");
        response.append("<title>Directory listing for ").append(dir).append("</title>");
        response.append("<script>");
        response.append("function addBaseUrl(url) {");
        response.append("  const baseUrl = window.location.origin;");
        response.append("  return baseUrl + url;");
        response.append("}");
        response.append("</script>");
        response.append("</head>");
        response.append("<body>");
        response.append("<h1>Directory listing for ").append(dir).append("</h1>");
        response.append("<hr>");
        response.append("<ul>");

        File[] files = requestedDir.listFiles();
        if (files != null) {
            for (File file : files) {
                response.append("<li>");
                if (file.isDirectory()) {
                    response.append("<a href=\"?dir=").append(dir);
                    if (!dir.endsWith("/")) {
                        response.append("/");
                    }
                    response.append(file.getName()).append("/\">").append(file.getName()).append("/</a>");
                } else {
                    response.append("<a href=\"javascript:void(0);\" onclick=\"window.location.href=addBaseUrl('").append(dir);
                    if (!dir.endsWith("/")) {
                        response.append("/");
                    }
                    response.append(file.getName()).append("');\">").append(file.getName()).append("</a>");
                }
                response.append("</li>");
            }
        } else {
            response.append("Failed to list contents of the directory.");
        }

        response.append("</ul>");
        response.append("<hr>");
        response.append("</body>");
        response.append("</html>");
        return response.toString();
    }
}
