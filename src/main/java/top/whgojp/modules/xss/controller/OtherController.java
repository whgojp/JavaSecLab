package top.whgojp.modules.xss.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import top.whgojp.common.constant.SysConstant;
import top.whgojp.common.utils.R;
import cn.hutool.core.date.DateUtil;
import top.whgojp.common.utils.UploadUtil;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

/**
 * @description 跨站脚本-其他场景
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/23 13:59
 */
@Slf4j
@Api(value = "OtherController", tags = "跨站脚本-其他场景")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/xss/other")
public class OtherController {
    @Autowired
    private ResourceLoader resourceLoader;

    @RequestMapping("")
    public String xssOther() {
        return "vul/xss/other";
    }

    @RequestMapping("/jquery-xss")
    public String jqueryXss() {
        return "vul/xss/jquery-xss";
    }

    @RequestMapping("/receive")
    @ResponseBody
    public R hackCookie(@RequestParam String cookie, HttpServletRequest request) {
        String currentTime = DateUtil.now();
        String remoteHost = request.getRemoteHost();

        String logMessage = "Data: " + currentTime + " Source IP: " + remoteHost + " User Cookie: " + cookie;
        log.info("Data: " + currentTime + " Source IP: " + remoteHost + " User Cookie: " + cookie);
        String filePath = "src/main/resources/static/other/cookie.txt";

        // 使用 try-with-resources 来自动关闭 FileWriter 和 BufferedWriter
        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(filePath), StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            writer.write(logMessage);
            writer.newLine(); // 换行
        } catch (IOException e) {
            e.printStackTrace(); // 这里可以根据实际情况处理异常
        }
        return R.ok(cookie);
    }

    @Autowired
    private UploadUtil uploadUtil;

    @Autowired
    private MessageSource messageSource;

    // 文件上传接口
    @ApiOperation(value = "漏洞场景：文件上传导致存储XSS", notes = "上传可被浏览器或预览服务解析的文件，后续访问文件时可能触发XSS")
    @RequestMapping("/vul1Upload")
    @ResponseBody
    @SneakyThrows
    public R vul1Upload(@RequestParam("file") MultipartFile file,
                                             @ApiParam(name = "type", value = "类型", required = true) @RequestParam String type,
                                             HttpServletRequest request) {
        String res;
        String suffix = FilenameUtils.getExtension(file.getOriginalFilename());
        String path = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort()+"/file/" ;
        switch (type) {
            case "xml":
                try {
                    if ("xml".equals(type)) {
                        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                        DocumentBuilder builder = factory.newDocumentBuilder();
                        org.w3c.dom.Document document = builder.parse(file.getInputStream());
                        StringWriter writer = new StringWriter();
                        javax.xml.transform.Transformer transformer = javax.xml.transform.TransformerFactory.newInstance().newTransformer();
                        transformer.transform(new DOMSource(document), new StreamResult(writer));
                        String xmlString = writer.toString();
                        log.info("解析后的XML内容：" + xmlString);
                    }
                } catch (Exception e) {
                    return R.error(msg("xss.other.upload.parseFailed", e.getMessage()));
                }
            // XML解析成功后继续落盘，便于演示“解析 + 可访问文件”组合场景。
            case "html":
            case "svg":
            case "pdf":
            case "swf":
                log.info("后缀名：" + suffix);
                res = uploadUtil.uploadFileAndReturnUrl(file, suffix,path);
                return R.ok(msg("xss.other.upload.success", res));
            default:
                return R.error(msg("xss.other.upload.invalid"));
        }
    }
    @ApiOperation(value = "漏洞场景：模板引擎不安全渲染导致XSS", notes = "th:utext会把内容作为HTML渲染，th:text会进行转义")
    @GetMapping("/vul2OtherTemplate")
    public String vul2OtherTemplate(@RequestParam("payload") String payload,
                                          @RequestParam("type") String type, Model model) {
        if ("html".equals(type)) {
            model.addAttribute("html", payload);
        } else if ("text".equals(type)) {
            model.addAttribute("text", payload);
        }
        return "vul/xss/other";
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
