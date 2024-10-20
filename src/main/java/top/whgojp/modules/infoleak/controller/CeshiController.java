package top.whgojp.modules.infoleak.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * @description 敏感信息泄漏-测试页面
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/19 13:07
 */
@Slf4j
@Api(value = "CeshiController", tags = "敏感信息泄漏-测试页面")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/infoLeak/ceShiPage")
public class CeshiController {
    @RequestMapping("")
    public String CeShi() {
        return "vul/infoleak/ceshi";
    }
    @RequestMapping("/pingPage")
    public String pingPage(){
        return "vul/infoleak/ping";
    }
    @GetMapping("/ping")
    public String ping(@RequestParam(name = "ip", required = false) String ip, Model model) {
        String result = "";
        if (ip != null && !ip.isEmpty()) {
            try {
                // 这里存在命令注入漏洞，用户输入没有经过过滤直接拼接到命令中执行
                log.info("测试命令："+ip);
                String command = "ping -c 4 " + ip;
//                Process process = Runtime.getRuntime().exec(command);
                Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                StringBuilder output = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                reader.close();
                result = output.toString();
            } catch (Exception e) {
                result = "Error: " + e.getMessage();
            }
        }
        model.addAttribute("result", result);
        return "vul/infoleak/ping";
    }

}
