package top.whgojp.modules.system.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @description Model实体-封装响应的JWT
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/14 02:07
 */
@AllArgsConstructor
@Getter
public class AuthenticationResponse {
    private final String jwt;
}