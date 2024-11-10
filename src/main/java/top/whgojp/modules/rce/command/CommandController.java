package top.whgojp.modules.rce.command;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
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
import java.util.Arrays;
import java.util.List;
import java.util.Map;

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
        // 获取 ProcessImpl 类对象
        Class<?> clazz = Class.forName("java.lang.ProcessImpl");

        // 获取 start 方法
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
    }


    // 可执行命令白名单
    private static final List<String> ALLOWED_COMMANDS = Arrays.asList("ls", "date");

    @RequestMapping("/safe")
    @ResponseBody
    public R safe(@RequestParam("payload") String payload) throws IOException {
        // 验证命令是否在允许的列表中
        if (!ALLOWED_COMMANDS.contains(payload)) {
            return R.error("不允许执行该命令！");
        }
        String[] cmdArray = { "sh", "-c", payload };
        ProcessBuilder pb = new ProcessBuilder(cmdArray);
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


}
