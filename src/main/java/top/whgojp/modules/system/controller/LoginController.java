package top.whgojp.modules.system.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.ShearCaptcha;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.annotation.AuthIgnore;
import top.whgojp.common.enums.LoginError;
import top.whgojp.common.utils.JwtUtil;
import top.whgojp.modules.system.entity.AuthenticationRequest;
import top.whgojp.modules.system.entity.AuthenticationResponse;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.UUID;

/**
 * @description 登录处理
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/16 21:45
 */
@Slf4j
@Controller
public class LoginController {
    @Resource
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtil jwtUtil;

    @RequestMapping({"/","/index","/homePage"})
    public String index(){
        return "index";
    }

    @RequestMapping("/login")
    public String login(HttpServletRequest request, Model model){
        LoginError loginError = determineErrorType(request);

        model.addAttribute("errorMessage", loginError != null ? loginError.getMessage() : null);

        return "login";
    }
    private LoginError determineErrorType(HttpServletRequest request) {
        String typeStr = request.getParameter("error");

        return typeStr == null ? null : LoginError.resolve(Integer.valueOf(typeStr));
    }



    @AuthIgnore
    @GetMapping("/captcha")
    public void captcha(HttpSession session, HttpServletResponse response) throws Exception {
        response.setContentType("image/jpeg");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache");

        //定义图形验证码的长、宽、验证码字符数、干扰线宽度
        ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(90, 30,4,3);
        try {
            //输出
            shearCaptcha.write(response.getOutputStream());

            String captchaCode = shearCaptcha.getCode();
            session.setAttribute("captcha", captchaCode);
            log.info("session id {}， 生成的验证码 {}", session.getId(), captchaCode);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @AuthIgnore
    @GetMapping("/hello")
    @ResponseBody
    public String hello() {
        return "this is resource";
    }


    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> createAuthenticateToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        Authentication authenticate = null;
        try {
            // 这里一步就是校验用户身份，点进去这个 authenticate（默认是 ProviderManager 这个实现类）
            // 它的参数类型是一个 Authentication，即传入一个未认证的 Authentication 进去，返回一个
            // 已经认证的 Authentication 出来
            authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authenticationRequest.getUsername(),
                            authenticationRequest.getPassword()
                    )
            );
        } catch (BadCredentialsException e) {
            throw new Exception("登陆错误", e);
        }

        // 补充知识 使用局部变量修饰 final 的好处
        // 1、访问局部变量要比访问成员变量要快
        // 2、访问局部变量要比每次调用方法去获取对象要快
        // 3、使用final修饰可以避免变量被重新赋值（引用赋值）
        // 4、使用final修饰时，JVM不用去跟踪该引用是否被更改？

        // 其实如果上面已经认证通过了，这里的 (UserDetails) authenticate.getPrincipal() 其实也可以使用下面这个方式取得
        // final UserDetails userDetails = myDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        // 不过有些时候会在 AuthenticationProvider 里面注入一些权限角色进这个 UserDetails 里面的 getAuthorities(); 方法里面
        final String jwt = jwtUtil.generateToken((UserDetails) authenticate.getPrincipal());
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

    // 退出接口
    // TODO: 2024/6/16 这里怎么获取用户名呢？
    @RequestMapping("/logout_success")
    public String logoutSuccess(Model model) {
        model.addAttribute("username", "admin");
        return "login";
    }




}
