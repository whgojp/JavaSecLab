package top.whgojp.modules.deserialize.xmldecoder.controller;

import io.swagger.annotations.Api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.xml.sax.InputSource;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * @description 反序列化 - XMLDecoder
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/19 19:53
 */
@Slf4j
@Api(value = "XMLDecoderController", tags = "反序列化 - XMLDecoder")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/xmlDecoder")
public class XMLDecoderController {
    @RequestMapping("")
    public String xmlDecoder() {
        return "vul/deserialize/xmlDecoder";
    }

    @RequestMapping("/vul")
    @ResponseBody
    public R vul(String payload) {
        String[] strCmd = payload.split(" ");
        StringBuilder xml = new StringBuilder()
                .append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                .append("<java version=\"1.8.0_151\" class=\"java.beans.XMLDecoder\">")
                .append("<object class=\"java.lang.ProcessBuilder\">")
                .append("<array class=\"java.lang.String\" length=\"").append(strCmd.length).append("\">");
        for (int i = 0; i < strCmd.length; i++) {
            xml.append("<void index=\"").append(i).append("\"><string>")
                    .append(strCmd[i]).append("</string></void>");
        }
        xml.append("</array><void method=\"start\" /></object></java>");
        try {
            new java.beans.XMLDecoder(new ByteArrayInputStream(xml.toString().getBytes(StandardCharsets.UTF_8)))
                    .readObject().toString();
            return R.ok("[+]命令执行成功");
        } catch (Exception e) {
            return R.error("[-]命令执行失败: " + e.getMessage());
        }
    }


    @RequestMapping("/safe")
    @ResponseBody
    public R safe(@RequestParam String payload) {
        try {
            // 构建 XML 字符串
            StringBuilder xml = new StringBuilder()
                    .append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                    .append("<java version=\"1.8.0_151\" class=\"java.beans.XMLDecoder\">")
                    .append("<object class=\"java.lang.ProcessBuilder\">")
                    .append("<array class=\"java.lang.String\" length=\"").append(payload.split(" ").length).append("\">");

            for (int i = 0; i < payload.split(" ").length; i++) {
                xml.append("<void index=\"").append(i).append("\"><string>")
                        .append(payload.split(" ")[i]).append("</string></void>");
            }

            xml.append("</array><void method=\"start\" /></object></java>");

            // 使用 SAX 解析器解析 XML
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser saxParser = factory.newSAXParser();
            CommandHandler handler = new CommandHandler();

            // 将 ByteArrayInputStream 包装成 InputSource
            InputSource inputSource = new InputSource(new ByteArrayInputStream(xml.toString().getBytes(StandardCharsets.UTF_8)));
            saxParser.parse(inputSource, handler);

            // 获取解析后的命令参数
            List<String> args = handler.getArgs();

            // 处理解析后的命令参数
            System.out.println("Parsed command: " + String.join(" ", args));

            return R.ok("[+]命令解析成功:"+String.join(" ", args));
        } catch (Exception e) {
            return R.error("[-]命令解析失败: " + e.getMessage());
        }
    }

    // SAX 处理器
    static class CommandHandler extends DefaultHandler {
        private List<String> args = new ArrayList<>();
        private boolean inString = false;

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            if ("string".equals(qName)) {
                inString = true;
            }
        }

        @Override
        public void characters(char[] ch, int start, int length) throws SAXException {
            if (inString) {
                args.add(new String(ch, start, length));
            }
        }

        @Override
        public void endElement(String uri, String localName, String qName) throws SAXException {
            if ("string".equals(qName)) {
                inString = false;
            }
        }

        public List<String> getArgs() {
            return args;
        }
    }
}
