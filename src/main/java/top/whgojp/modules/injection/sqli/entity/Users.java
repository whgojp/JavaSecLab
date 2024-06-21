package top.whgojp.modules.injection.sqli.entity;

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
 * @TableName users
 */
@TableName(value ="users")
@Data
@AllArgsConstructor
@ApiModel(value = "用户实体类",description = "test")
public class Users implements Serializable {
    /**
     * 
     */
    @TableId(type = IdType.AUTO)
    @ApiModelProperty(value = "用户ID",required = true)
    private Integer id;

    /**
     * 
     */
    @ApiModelProperty(value = "用户名",example = "whgojp")
    private String user;

    /**
     * 
     */
    @ApiModelProperty(value = "密码",example = "12345")
    private String pass;

    @TableField(exist = false)
    private static final long serialVersionUID = 1L;
}