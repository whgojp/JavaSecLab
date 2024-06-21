package top.whgojp.common.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/21 19:56
 */
public class CustomAuthenticationException extends AuthenticationException {

    public CustomAuthenticationException(String msg){
        super(msg);
    }
}
