package top.whgojp.security.detail;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;
import java.util.Collection;

/**
 * @Description //TODO $
 * @Date 21:13
 * @Author whgojp@foxmail.com
 **/
@EqualsAndHashCode(callSuper = true)
public class CustomUserDetailsUser extends User implements Serializable {

    private String userId;

    public CustomUserDetailsUser(String userId,String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.userId = userId;
    }
}
