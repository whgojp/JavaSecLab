package top.whgojp.modules.deserialize.xmldecoder.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

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

    @RequestMapping("/vulXmlDecoder")
    @ResponseBody
    public R vulXmlDecoder(String payload) {
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
            return R.ok("命令执行成功");
        } catch (Exception e) {
            return R.error("命令执行失败: " + e.getMessage());
        }
    }


}
