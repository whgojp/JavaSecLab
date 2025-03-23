package top.whgojp.modules.infoleak.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @description 敏感信息泄漏-Js文件泄漏敏感信息
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/17 19:00
 */
@Slf4j
@Api(value = "JsFileLeakController", tags = "敏感信息泄漏-Js文件泄漏敏感信息")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/infoLeak/js")
public class JsFileLeakController {
    @RequestMapping("")
    public String jsLeak() {
        return "vul/infoleak/jsLeak";
    }
    @RequestMapping("/hard-coding")
    public String hardCoding(){
        return "vul/infoleak/hard-coding";
    }
    @RequestMapping("/loginSuccess")
    public String loginSuccess(){
        return "vul/infoleak/loginSuccess";
    }

}
