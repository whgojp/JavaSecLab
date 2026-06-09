package top.whgojp.modules.rce.command;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @description RCE - 命令注入
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/23 09:49
 */
@Slf4j
@Api(value = "CommandController", tags = "RCE - 命令注入")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/command")
public class CommandController {
    private final MessageSource messageSource;

    // Map business actions to fixed command arguments. Users cannot directly control command strings.
    private static final Map<String, List<String>> ALLOWED_COMMANDS = new HashMap<>();

    static {
        ALLOWED_COMMANDS.put("list", Arrays.asList("ls"));
        ALLOWED_COMMANDS.put("date", Arrays.asList("date"));
    }

    public CommandController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String spel() {
        return "vul/rce/command";
    }

    @RequestMapping("/vul1")
    @ResponseBody
    public R vul1(@RequestParam("payload") String payload) throws IOException {
        String[] command = {"sh", "-c", payload};

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        Process process = pb.start();
        InputStream inputStream = process.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        StringBuilder output = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return R.ok(output.toString());
    }

    @RequestMapping("/vul2")
    @ResponseBody
    public R vul2(String payload) throws IOException {
        StringBuilder sb = new StringBuilder();
        String line;
        Process proc = Runtime.getRuntime().exec(payload);
        InputStream inputStream = proc.getInputStream();
        InputStreamReader isr = new InputStreamReader(inputStream);
        BufferedReader br = new BufferedReader(isr);
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        return R.ok(sb.toString());
    }

    @RequestMapping("/vul3")
    @ResponseBody
    public R vul3(String payload) throws Exception {
        try {
            // Get the ProcessImpl class object.
            Class<?> clazz = Class.forName("java.lang.ProcessImpl");

            // Get the start method.
            Method method = clazz.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
            method.setAccessible(true);

            Process process = (Process) method.invoke(null, new String[]{payload}, null, null, null, false);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return R.ok(output.toString());
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            return R.error(msg("rce.result.processImplRestricted", e.getMessage()));
        }
    }

    @RequestMapping("/safe")
    @ResponseBody
    public R safe(@RequestParam("payload") String payload) throws IOException {
        List<String> command = ALLOWED_COMMANDS.get(payload);
        if (command == null) {
            return R.error(msg("rce.result.actionNotAllowed"));
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        try {
            if (!process.waitFor(3, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return R.error(msg("rce.result.commandTimeout"));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return R.error(msg("rce.result.commandInterrupted"));
        }
        String output = readProcessOutput(process);
        return R.ok(output);
    }

    private String readProcessOutput(Process process) throws IOException {
        try (InputStream inputStream = process.getInputStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        }
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
