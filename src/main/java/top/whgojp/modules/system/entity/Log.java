package top.whgojp.modules.system.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import java.io.Serializable;
import java.util.Date;
import lombok.Data;

/**
 * 
 * @TableName log
 */
@TableName(value ="log")
@Data
public class Log implements Serializable {
    /**
     * log_id
     */
    @TableId
    private String logid;

    /**
     * 用户名
     */
    private String username;

    /**
     * 用户操作
     */
    private String optionname;

    /**
     * 操作终端
     */
    private String optionterminal;

    /**
     * Ip地址
     */
    private String optionip;

    /**
     * 创建时间
     */
    private Date optiontime;

    @TableField(exist = false)
    private static final long serialVersionUID = 1L;
}