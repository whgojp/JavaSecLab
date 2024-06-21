package top.whgojp.modules.system.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @description Model实体-用于封装请求参数
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/14 02:06
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {
    private String username;
    private String password;
}