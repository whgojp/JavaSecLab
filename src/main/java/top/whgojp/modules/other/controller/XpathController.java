package top.whgojp.modules.other.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import top.whgojp.common.utils.R;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;

/**
 * @description 其他漏洞-XPATH注入
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/11/10 00:18
 */
@Slf4j
@Api(value = "DosController", tags = "其他漏洞-XPATH注入")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/other/xpath")
public class XpathController {

    private final MessageSource messageSource;

    public XpathController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String xpath() {
        return "vul/other/xpath";
    }

    @RequestMapping("/vul")
    @ResponseBody
    public R vul(@RequestParam String username, @RequestParam String password) {
        try {
            // 构造 XML 数据
            String xmlData = "<users><user><username>admin</username><password>password</password></user></users>";

            // 解析 XML 文档
            DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));

            // 构造 XPath 表达式（存在注入漏洞）
            XPath xpath = XPathFactory.newInstance().newXPath();
            String expression = "/users/user[username='" + username + "' and password='" + password + "']";
            NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);
            if (nodes.getLength() > 0) {
                log.info("[vul] XPath injection succeeded; user verification passed.");
                return R.ok(msg("other.xpath.result.success", username));
            } else {
                log.info("[vul] XPath injection failed; username or password is incorrect.");
                return R.ok(msg("other.xpath.result.invalid"));
            }
        } catch (Exception e) {
            log.error("[vul] Exception occurred: {}", e.getMessage(), e);
            return R.error(msg("other.xpath.result.exception", e.getMessage()));
        }
    }

    @PostMapping("/safe")
    @ResponseBody
    public R safe(@RequestParam("username") String username, @RequestParam("password") String password) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            String xml = "<users><user><username>admin</username><password>password</password></user></users>";
            Document doc = builder.parse(new InputSource(new StringReader(xml)));

            XPath xpath = XPathFactory.newInstance().newXPath();
            xpath.setXPathVariableResolver(variableName -> resolveXPathVariable(variableName, username, password));
            String expression = "/users/user[username=$username and password=$password]";
            NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);

            if (nodes.getLength() > 0) {
                return R.ok(msg("other.xpath.result.success", username));
            } else {
                return R.error(msg("other.xpath.result.authFailed"));
            }
        } catch (Exception e) {
            e.printStackTrace();
            return R.error(msg("other.xpath.result.serverError", e.getMessage()));
        }
    }

    private Object resolveXPathVariable(QName variableName, String username, String password) {
        if ("username".equals(variableName.getLocalPart())) {
            return username;
        }
        if ("password".equals(variableName.getLocalPart())) {
            return password;
        }
        return "";
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

}
