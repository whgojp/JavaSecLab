package top.whgojp.modules.loginconfront.controller;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * @description 登录对抗-凭证安全
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/11/19 22:28
 */
@Slf4j
@Api(value = "CredentialController", tags = "登录对抗-凭证安全")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/loginconfront/credential")
public class CredentialController {
    @RequestMapping("")
    public String credential() {
        return "vul/loginconfront/credential";
    }

    // 生成一个符合HS256要求的强密钥（至少256位）
    @Value("${jwt.key}")
    String secretKey = "f3a4c6d5b9bfeff28b1f529b0840134bcd4183474e2d4a97c05615a134e4f4da";
    Key key = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName());

//    Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    @GetMapping("/generate-jwt")
    @ResponseBody
    public R generateJWT(String username, String role) {
        String jwt = Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .signWith(key)
                .compact();
        log.info("生成的JWT: " + jwt);
        return R.ok(jwt);
    }

    @RequestMapping("/vul1")
    @ResponseBody
    public R vul1(@RequestHeader("Auth_Token") String jwt) {  // 从请求头获取 JWT
        log.info("获取到的JWT：" + jwt);
        try {
            String user = Jwts.parser()
                    .setSigningKey(key)
                    .parseClaimsJws(jwt)
                    .getBody()
                    .getSubject();
            String role = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody()
                    .get("role", String.class);

            log.info("JWT解析成功，用户：" + user);
            return R.ok("JWT解析成功，user：" + user+",role："+role);
        } catch (Exception e) {
            log.info("JWT解析失败：" + e.getMessage());
            return R.error("JWT解析失败：" + e.getMessage());
        }
    }

    @RequestMapping("/vul2")
    public R vul2() {
        return R.ok();
    }

}
