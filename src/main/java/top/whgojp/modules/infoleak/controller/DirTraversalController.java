package top.whgojp.modules.infoleak.controller;

import io.swagger.annotations.Api;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.constant.SysConstant;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Comparator;

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
    private final MessageSource messageSource;

    public DirTraversalController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String DirTraversal() {
        return "vul/infoleak/dirTraversal";
    }

    @GetMapping("/vul")
    @ResponseBody
    public String vul(@RequestParam(defaultValue = "/") String dir) {
        File baseDir = resolveStaticBaseDir();
        File requestedDir = new File(baseDir, dir);

        return renderDirectoryListing(dir, requestedDir, false);
    }

    @GetMapping("/safe1")
    @ResponseBody
    @SneakyThrows
    public String safe1(@RequestParam(defaultValue = "/") String dir) {
        File baseDir = resolveStaticBaseDir();

        String decodedDir = URLDecoder.decode(dir, StandardCharsets.UTF_8.name());

        // 进行敏感字符过滤，禁止使用 '.'、';'、'\' 和 '%'
        if (decodedDir.contains(".") || decodedDir.contains(";") || decodedDir.contains("\\") || decodedDir.contains("%")) {
            return msg("infoleak.dir.result.illegal");
        }
        File requestedDir = new File(baseDir, dir);

        return renderDirectoryListing(dir, requestedDir, false);
    }

    @GetMapping("/safe2")
    @ResponseBody
    public String safe2(@RequestParam(defaultValue = "/") String dir) {
        File baseDir = resolveStaticBaseDir();
        String relativeDir = normalizeRelativeDir(dir);

        // 检查请求的目录是否在规定目录内
        try {
            Path basePath = baseDir.getCanonicalFile().toPath();
            File requestedDir = new File(baseDir, relativeDir);
            Path requestedPath = requestedDir.getCanonicalFile().toPath();
            if (!requestedPath.startsWith(basePath) || !requestedDir.isDirectory()) {
                return "Directory not found or access denied.";
            }
            return renderDirectoryListing(dir, requestedDir, true);
        } catch (IOException e) {
            return "Error resolving directory path.";
        }
    }

    private File resolveStaticBaseDir() {
        File configuredDir = new File(sysConstant.getStaticFolder());
        if (configuredDir.isDirectory() && hasVisibleFiles(configuredDir)) {
            return configuredDir;
        }

        try {
            java.net.URL resource = getClass().getClassLoader().getResource("static");
            if (resource != null && "file".equals(resource.getProtocol())) {
                return new File(resource.toURI());
            }
        } catch (URISyntaxException e) {
            log.warn("Failed to resolve classpath static directory.", e);
        }

        return configuredDir;
    }

    private boolean hasVisibleFiles(File dir) {
        File[] files = dir.listFiles(file -> !file.isHidden());
        return files != null && files.length > 0;
    }

    private String normalizeRelativeDir(String dir) {
        if (dir == null || dir.isEmpty() || "/".equals(dir)) {
            return "";
        }
        return dir.startsWith("/") ? dir.substring(1) : dir;
    }

    private String renderDirectoryListing(String displayDir, File requestedDir, boolean keepInsideBase) {
        String normalizedDisplayDir = displayDir == null || displayDir.isEmpty() ? "/" : displayDir;
        StringBuilder response = new StringBuilder();
        response.append("<!DOCTYPE HTML>");
        response.append("<html lang=\"en\">");
        response.append("<head>");
        response.append("<meta charset=\"utf-8\">");
        String listingTitle = msg("infoleak.dir.result.listingTitle");
        response.append("<title>").append(escapeHtml(listingTitle)).append(" ").append(escapeHtml(normalizedDisplayDir)).append("</title>");
        response.append("</head>");
        response.append("<body>");
        response.append("<h1>").append(escapeHtml(listingTitle)).append(" ").append(escapeHtml(normalizedDisplayDir)).append("</h1>");
        response.append("<hr>");
        response.append("<ul>");

        File[] files = requestedDir.listFiles();
        if (files != null) {
            Arrays.sort(files, Comparator.comparing(File::isFile).thenComparing(File::getName));
            for (File file : files) {
                response.append("<li>");
                String itemName = file.getName();
                String childDir = appendPath(normalizedDisplayDir, itemName, file.isDirectory());
                if (file.isDirectory()) {
                    response.append("<a href=\"?dir=").append(urlEncode(childDir)).append("\">")
                            .append(escapeHtml(itemName)).append("/</a>");
                } else {
                    if (keepInsideBase) {
                        response.append(escapeHtml(itemName));
                    } else {
                        response.append("<a href=\"").append(escapeHtml(childDir)).append("\">")
                                .append(escapeHtml(itemName)).append("</a>");
                    }
                }
                response.append("</li>");
            }
        } else {
            response.append(escapeHtml(msg("infoleak.dir.result.failed")));
        }

        response.append("</ul>");
        response.append("<hr>");
        response.append("</body>");
        response.append("</html>");
        return response.toString();
    }

    private String appendPath(String dir, String name, boolean directory) {
        String prefix = (dir == null || dir.isEmpty() || "/".equals(dir)) ? "/" : dir + (dir.endsWith("/") ? "" : "/");
        return prefix + name + (directory ? "/" : "");
    }

    private String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name()).replace("+", "%20");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 encoding is not supported", e);
        }
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }
}
