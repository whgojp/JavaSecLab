package top.whgojp.modules.sqli.mapper;

import org.apache.ibatis.jdbc.SQL;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/30 14:51
 */
public class SqliProvider {
    public String selectUserById(Integer id) {
        return new SQL(){{
            SELECT("*");
            FROM("sqli");
            WHERE("id = #{id}");
        }}.toString();
    }
}