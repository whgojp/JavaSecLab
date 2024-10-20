package top.whgojp.modules.sqli.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import java.io.Serializable;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 
 * @TableName sqli
 */
@TableName(value ="sqli")
@Data
@AllArgsConstructor
@ApiModel(value = "SQL注入测试表",description = "sql injection test table for mybatis")
public class Sqli implements Serializable {
    /**
     * 
     */
    @TableId(type = IdType.AUTO)
    @ApiModelProperty(value = "用户ID",required = true)
    private Integer id;

    /**
     * 用户名
     */
    @ApiModelProperty(value = "用户名",example = "whgojp")
    private String username;

    /**
     * 密码
     */
    @ApiModelProperty(value = "密码",example = "12345")
    private String password;

    @TableField(exist = false)
    private static final long serialVersionUID = 1L;
}