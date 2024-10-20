package top.whgojp.modules.rce.code;

import groovy.lang.GroovyShell;
import groovy.lang.Script;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import java.util.Arrays;
import java.util.List;

/**
 * @description RCE - 代码注入
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/23 09:49
 */
@Slf4j
@Api(value = "CodeController", tags = "RCE - 代码注入")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/code")
public class CodeController {
    @RequestMapping("")
    public String code() {
        return "vul/rce/code";
    }

    @GetMapping("/vulGroovy")
    @ResponseBody
    public R vulGroovy(String payload) {
        log.info("[+] Groovy代码执行：" + payload);
        try {
            GroovyShell shell = new GroovyShell();
            Object result = shell.evaluate(payload);
            if (result instanceof Process) {
                Process process = (Process) result;
                String output = getProcessOutput(process);
                return R.ok("[+] Groovy代码执行，结果：" + output);
            } else {
                return R.ok("[+] Groovy代码执行，结果：" + result.toString());
            }
        } catch (Exception e) {
            return R.error(e.getMessage());
        }
    }

    @GetMapping("/safeGroovy")
    @ResponseBody
    public R safeGroovy(String payload) {
        List<String> trustedScripts = Arrays.asList(
                "\"id\".execute()",
                "\"ls\".execute()",
                "\"whoami\".execute()"
        );
        if (!isTrustedScript(payload, trustedScripts)) {
            return R.error("非法的脚本输入！");
        }
        try {
            GroovyShell shell = new GroovyShell();
            Object result = shell.evaluate(payload);
            if (result instanceof Process) {
                Process process = (Process) result;
                String output = getProcessOutput(process);
                return R.ok("[+] 执行受信任的脚本，结果：" + output);
            } else {
                return R.ok("[+] 执行受信任的脚本，结果：" + result.toString());
            }
        } catch (Exception e) {
            return R.error(e.getMessage());
        }
    }
    private boolean isTrustedScript(String script, List<String> trustedScripts) {
        return trustedScripts.contains(script);
    }
    private String getProcessOutput(Process process) {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        } catch (Exception e) {
            return "读取输出失败: " + e.getMessage();
        }
        return output.toString();
    }


}
