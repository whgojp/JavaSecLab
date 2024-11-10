package top.whgojp.modules.other.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import top.whgojp.common.utils.R;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
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
                log.info("[vul] XPath 注入成功，用户验证通过！");
                return R.ok("用户名和密码验证通过！欢迎："+username);
            } else {
                log.info("[vul] XPath 注入失败，用户名或密码错误！");
                return R.ok("用户名或密码错误！");
            }
        } catch (Exception e) {
            log.error("[vul] 发生异常：" + e.getMessage(), e);
            return R.error("发生异常：" + e.getMessage());
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

            String escapedUsername = StringEscapeUtils.escapeXml10(username);
            String escapedPassword = StringEscapeUtils.escapeXml10(password);

            XPath xpath = XPathFactory.newInstance().newXPath();
            String expression = "/users/user[username='" + escapedUsername + "' and password='" + escapedPassword + "']";
            NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);

            if (nodes.getLength() > 0) {
                return R.ok("用户名和密码验证通过！欢迎：" + escapedUsername);
            } else {
                return R.error("认证失败：用户名或密码错误");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return R.error("服务器内部错误：" + e.getMessage());
        }
    }

}
