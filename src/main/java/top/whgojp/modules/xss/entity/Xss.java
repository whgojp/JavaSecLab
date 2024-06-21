package top.whgojp.modules.xss.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 
 * @TableName xss
 */
@TableName(value ="xss")
@Data
@AllArgsConstructor
public class Xss implements Serializable {
    /**
     * 主键id
     */
    @TableId
    private Integer id;

    /**
     * 插入内容
     */
    private String content;

    /**
     * 插入时间
     */
    private String date;

    @TableField(exist = false)
    private static final long serialVersionUID = 1L;
}