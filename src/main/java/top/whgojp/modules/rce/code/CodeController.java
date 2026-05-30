package top.whgojp.modules.rce.code;

import groovy.lang.GroovyShell;
import groovy.lang.Script;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

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
    private final MessageSource messageSource;

    public CodeController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String code() {
        return "vul/rce/code";
    }

    @GetMapping("/vulGroovy")
    @ResponseBody
    public R vulGroovy(String payload) {
        log.info("[+] Groovy code execution: {}", payload);
        try {
            GroovyShell shell = new GroovyShell();
            Object result = shell.evaluate(payload);
            if (result instanceof Process) {
                Process process = (Process) result;
                String output = getProcessOutput(process);
                return R.ok(msg("rce.result.groovyExecution", output));
            } else {
                return R.ok(msg("rce.result.groovyExecution", result.toString()));
            }
        } catch (Exception e) {
            return R.error(e.getMessage());
        }
    }

    @GetMapping("/safeGroovy")
    @ResponseBody
    public R safeGroovy(String payload) {
        if ("hello".equals(payload)) {
            return R.ok(msg("rce.result.controlledAction", "Hello JavaSecLab"));
        }
        if ("time".equals(payload)) {
            return R.ok(msg("rce.result.controlledAction", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)));
        }
        if ("sum".equals(payload)) {
            return R.ok(msg("rce.result.controlledAction", (1 + 2 + 3)));
        }
        return R.error(msg("rce.result.illegalAction"));
    }

    private String getProcessOutput(Process process) {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        } catch (Exception e) {
            return msg("rce.result.readOutputFailed", e.getMessage());
        }
        return output.toString();
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
