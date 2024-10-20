package top.whgojp.modules.xxe.controller;

import groovy.xml.SAXBuilder;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;
import top.whgojp.common.utils.R;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.StringReader;
import java.io.StringWriter;

/**
 * @description XML外部实体注入
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/29 11:27
 */
@Slf4j
@Api(value = "XXEController", tags = "XML外部实体注入")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/xxe")
public class XXEController {

    @RequestMapping("/vul")
    public String xxeVul() {
        return "vul/xxe/xxe-vul";
    }
    @RequestMapping("/safe")
    public String xxeSafe() {
        return "vul/xxe/xxe-safe";
    }
    @RequestMapping(value = "/vulXMLReader")
    @ResponseBody
    public String vulXMLReader(@RequestParam String payload) {
        try {
            XMLReader xmlReader = XMLReaderFactory.createXMLReader();
            StringWriter stringWriter = new StringWriter();
            xmlReader.setContentHandler(new DefaultHandler() {
                public void characters(char[] ch, int start, int length) {
                    for (int i = start; i < start + length; i++) {
                        if (ch[i] == '\n') {
                            stringWriter.write("<br/>");
                        } else {
                            stringWriter.write(ch[i]);
                        }
                    }
                }
            });
            xmlReader.parse(new InputSource(new StringReader(payload)));
            return stringWriter.toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    /**
     * javax.xml.parsers.SAXParser 是 XMLReader 的替代品，它提供了更多的安全措施，例如默认禁用 DTD 和外部实体的声明，如果需要使用 DTD 或外部实体，可以手动启用它们，并使用相应的安全措施
     */
    @RequestMapping(value = "/vulSAXParser")
    @ResponseBody
    public String vulSAXParser(@RequestParam String payload) {
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser parser = factory.newSAXParser();
            StringWriter stringWriter = new StringWriter();
            DefaultHandler handler = new DefaultHandler() {
                public void characters(char[] ch, int start, int length) {
                    for (int i = start; i < start + length; i++) {
                        if (ch[i] == '\n') {
                            stringWriter.write("<br/>");
                        } else {
                            stringWriter.write(ch[i]);
                        }
                    }
                }
            };
            parser.parse(new InputSource(new StringReader(payload)), handler);
            return stringWriter.toString();
        } catch (Exception e) {
            return e.toString();
        }
    }


//    @ApiOperation(value = "vul：xmlbeam")
//    @RequestMapping(value = "/xmlbeam")
//    public String handleCustomer(@RequestBody Customer customer) {
//        log.info("[vul] xmlbeam: " + customer);
//        return String.format("%s:%s login success!", customer.getFirstname(), customer.getLastname());
//    }
//
//    public interface Customer {
//        @XBRead("//username")
//        String getFirstname();
//
//        @XBRead("//password")
//        String getLastname();
//    }
//
//
//    @ApiOperation(value = "vul：SAXReader")
//    @RequestMapping(value = "/SAXReader")
//    public String SAXReader(@RequestParam String content) {
//        try {
//            SAXReader sax = new SAXReader();
//            // 修复：禁用外部实体
//            // sax.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
//            sax.read(new InputSource(new StringReader(content)));
//            return "SAXReader XXE";
//        } catch (Exception e) {
//            return e.toString();
//        }
//    }
//
//
//    @ApiOperation(value = "vul：SAXBuilder", notes = "是一个JDOM解析器，能将路径中的XML文件解析为Document对象")
//    @RequestMapping(value = "/SAXBuilder")
//    public String SAXBuilder(@RequestBody String content) {
//        try {
//            SAXBuilder saxbuilder = new SAXBuilder();
//            // saxbuilder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
//            saxbuilder.build(new InputSource(new StringReader(content)));
//            return "SAXBuilder XXE";
//        } catch (Exception e) {
//            return e.toString();
//        }
//    }
//
//
//    /**
//     * @poc http://127.0.0.1:8888/XXE/DocumentBuilder
//     * payload: <?xml version="1.0" encoding="utf-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><person><name>&xxe;</name></person>
//     */
//    @ApiOperation(value = "vul：DocumentBuilder类")
//    @RequestMapping(value = "/DocumentBuilder")
//    public String DocumentBuilder(@RequestParam String content) {
//        try {
//            // DocumentBuilderFactory是用于创建DOM模式的解析器对象,newInstance方法会根据本地平台默认安装的解析器，自动创建一个工厂的对象并返回。
//            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
//
//            DocumentBuilder builder = factory.newDocumentBuilder();
//            StringReader sr = new StringReader(content);
//            InputSource is = new InputSource(sr);
//            Document document = builder.parse(is);
//
//            NodeList nodeList = document.getElementsByTagName("person");
//            Element element = (Element) nodeList.item(0);
//            return String.format("姓名: %s", element.getElementsByTagName("name").item(0).getFirstChild().getNodeValue());
//
//        } catch (Exception e) {
//            return e.toString();
//        }
//    }
//
//
//    /**
//     * @poc http://127.0.0.1:8888/XXE/unmarshaller (POST)
//     * payload <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE student[<!ENTITY out SYSTEM "file:///etc/passwd">]><student><name>&out;</name></student>
//     */
//    @ApiOperation(value = "vul：Unmarshaller")
//    @RequestMapping(value = "/unmarshaller")
//    public String Unmarshaller(@RequestBody String content) {
//        try {
//
//            JAXBContext context = JAXBContext.newInstance(Student.class);
//            Unmarshaller unmarshaller = context.createUnmarshaller();
//
//            XMLInputFactory xif = XMLInputFactory.newFactory();
//            // 修复：禁用外部实体
//            // xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
//            // xif.setProperty(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
//
//            // 默认情况下在1.8版本上不能加载外部dtd文件，需要更改设置。
//            // xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
//            // xif.setProperty(XMLInputFactory.SUPPORT_DTD, true);
//            XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(content));
//
//            Object o = unmarshaller.unmarshal(xsr);
//            log.info("[vul] Unmarshaller: " + content);
//
//            return o.toString();
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return "出错了！";
//    }


    @RequestMapping(value = "/safeXMLReader")
    @ResponseBody
    public String safeXMLReader(@RequestParam String payload) {
        try {
            XMLReader xmlReader = XMLReaderFactory.createXMLReader();
            // 禁用外部实体引用，防止XXE攻击
            xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
            xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            StringWriter stringWriter = new StringWriter();
            xmlReader.setContentHandler(new DefaultHandler() {
                public void characters(char[] ch, int start, int length) {
                    for (int i = start; i < start + length; i++) {
                        if (ch[i] == '\n') {
                            stringWriter.write("<br/>");
                        } else {
                            stringWriter.write(ch[i]);
                        }
                    }
                }
            });
            xmlReader.parse(new InputSource(new StringReader(payload)));
            return stringWriter.toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    @RequestMapping(value = "/safeBlackList")
    @ResponseBody
    public String safeBlackList(@RequestParam String payload) {
        String[] black_list = {"ENTITY", "DOCTYPE"};
        for (String keyword : black_list) {
            if (payload.toUpperCase().contains(keyword)) {
                return "[+]检测到恶意XML！";
            }
        }
        return "[-]XML内容安全";
    }



}
