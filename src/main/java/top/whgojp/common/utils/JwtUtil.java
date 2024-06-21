package top.whgojp.common.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * @description JWT工具类
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/14 02:04
 */
@Component
public class JwtUtil {

    // 注意，这里使用 secretKeyFor 方法自动随机生成一个适合指定编码长度的密钥，避免硬编码出错，以及安全问题
    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    // 不过正式的开发环境，这个密钥最好不要这样搞，第一次生成之后记录下来就行了，不然每次重启服务一次，全部 JWT 都失效了

    public String extractUsername(String token) {
        // 这里直接引用 Claims 类里面的 getSubject 方法
        return extractClaim(token, Claims::getSubject);
    }

    /*
     它等价于下面这个
     public String extractUsername(String token) {
         return extractClaim(token, (Claims claims)-> {
             return claims.getSubject();
         });
     }
    */

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // 这个 Function 表示一个接受一个参数并产生结果的函数。
    // <T> 函数输入的类型（就是 apply 方法的参数类型）
    // <R> 函数结果的类型（就是 apply 方法的返回值）
    public <R> R extractClaim(String token, Function<Claims, R> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        // 这个 Function 函数接口通过调用 apply 取得结果
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                // 这里需要显示指定使用 HS256（注意，上面只是生成一个适合长度的密钥，本体它还是一个普通字串）
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        // 检查 token 里面的信息是否与 UserDetails 相同，这里可以写多几个认证，但是只是测试，所以象征性比对个用户名就行了
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}