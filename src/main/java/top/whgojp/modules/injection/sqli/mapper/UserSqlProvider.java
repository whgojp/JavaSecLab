package top.whgojp.modules.injection.sqli.mapper;

import org.apache.ibatis.jdbc.SQL;

import static org.apache.ibatis.jdbc.SqlBuilder.*;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/30 14:51
 */
public class UserSqlProvider {
    public String selectUserById(Integer id) {
        return new SQL(){{
            SELECT("*");
            FROM("users");
            WHERE("id = #{id}");
        }}.toString();
    }
}