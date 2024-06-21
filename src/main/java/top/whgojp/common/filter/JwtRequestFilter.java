package top.whgojp.common.filter;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/14 02:13
 */

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import top.whgojp.common.utils.JwtUtil;
import top.whgojp.security.detail.CustomUserDetailsService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OncePerRequestFilter 它能够确保在一次请求只通过一次 filter，而不需要重复执行
 **/
@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        // 标准的 Token 都是从这个 Authorization 里面取得数据的
        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        // 注意，一般它前面还有一个 “Bearer ”
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            // 尝试拿 token 中的 username
            // 若是没有 token 或者拿 username 时出现异常，那么 username 为 null
            username = jwtUtil.extractUsername(jwt);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // 用 UserDetailsService 从数据库中拿到用户的 UserDetails 类
            // UserDetails 类是 Spring Security 用于保存用户权限的实体类
            UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(username);

            // 检查用户带来的 token 是否有效
            // 包括 token 和 userDetails 中用户名是否一样， token 是否过期， token 生成时间是否在最后一次密码修改时间之前
            // 若是检查通过
            if (jwtUtil.validateToken(jwt, userDetails)) {

                // 生成通过认证的 Authentication
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(
                                // 一般不在这里填入密码
                                userDetails, null, userDetails.getAuthorities());

                // 将这个请求本体存入进去
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 将权限写入本次会话，这个 Context 会在当前这个线程有效（它内部维护着一个 ThreadLocal）
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }

        // 这里可以直接放行，反正后面 SpringSecurity 没有从上下文中取得这个请求的 usernamePasswordAuthenticationToken 也会将其拦截
        chain.doFilter(request, response);
    }
}