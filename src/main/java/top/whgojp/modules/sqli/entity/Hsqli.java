package top.whgojp.modules.sqli.entity;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;

import javax.persistence.*;

/**
 * @description Hibernate 实体类
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/5 17:18
 */
@Entity
@Data
@Table(name = "sqli")
@ApiModel(value = "SQL注入测试表",description = "sql injection test table for mybatis")
public class Hsqli {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @ApiModelProperty(value = "用户ID",required = true)
    private Long id;

    @ApiModelProperty(value = "用户名",example = "whgojp")
    private String username;
    @ApiModelProperty(value = "密码",example = "12345")
    private String password;
}
