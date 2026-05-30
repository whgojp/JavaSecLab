package top.whgojp.modules.sqli.controller;

import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import lombok.extern.slf4j.Slf4j;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.OracleCodec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Controller;
import top.whgojp.common.utils.CheckUserInput;
import top.whgojp.common.utils.R;
import io.swagger.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.web.bind.annotation.*;

import java.sql.*;
import java.util.List;
import java.util.Map;


/**
 * @description ORM框架-JDBC下的sql注入问题
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/27 21:46
 */
@Api(value = "JdbcController", tags = "SQL注入1-JDBC")
@Slf4j
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/sqli/jdbc")
public class JdbcController {
    @Autowired
    private CheckUserInput checkUserInput;

    //指定数据库地址、用户名、密码
    @Value("${spring.datasource.primary.url}")
    private String dbUrl;
    @Value("${spring.datasource.primary.username}")
    private String dbUser;
    @Value("${spring.datasource.primary.password}")
    private String dbPass;


    @RequestMapping("/jdbcVul")
    public String sqliJdbcVul() {
        return "vul/sqli/jdbcVul";
    }

    @RequestMapping("/jdbcSafe")
    public String sqliJdbcSafe() {
        return "vul/sqli/jdbcSafe";
    }

    @RequestMapping("/jdbcSpecial")
    public String sqliJdbcSpecial() {
        return "vul/sqli/jdbcSpecial";
    }

    @ApiOperation(value = "漏洞场景：JDBC-原生SQL语句拼接", notes = "原生sql语句动态拼接 参数未进行任何处理")
    @GetMapping("/vul1")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),     // 注意这里id是String类型
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    public R vul1(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        String sql = "";
        try {
            //注册数据库驱动类
            Class.forName("com.mysql.cj.jdbc.Driver");

            //调用DriverManager.getConnection()方法创建Connection连接到数据库
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);

            //调用Connection的createStatement()或prepareStatement()方法 创建Statement对象
            Statement stmt = conn.createStatement();
            int rowsAffected;
            String message;
            switch (type) {
                case "add":
                    message = checkUserInput.checkUser(username, password);
                    if (!message.isEmpty()) return R.error(message);
                    sql = "INSERT INTO sqli (username, password) VALUES ('" + username + "', '" + password + "')"; //这里没有标识id id自增长
                    log.info("当前执行数据插入操作:" + sql);
                    //通过Statement对象执行SQL语句，得到ResultSet对象-查询结果集
                    rowsAffected = stmt.executeUpdate(sql);         // 这里注意一下 insert、update、delete 语句应使用executeUpdate()
                    //关闭ResultSet结果集 Statement对象 以及数据库Connection对象 释放资源
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "Data inserted successfully. username:" + username + " password:" + password : "Data insertion failed.";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    sql = "DELETE FROM sqli WHERE id = '" + id + "'";
                    log.info("当前执行数据删除操作:" + sql);
                    rowsAffected = stmt.executeUpdate(sql);
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "Data deleted successfully." : "Delete failed. User ID: " + id + " does not exist.";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    message = checkUserInput.checkUser(username, password);
                    if (!message.isEmpty()) return R.error(message);
                    sql = "UPDATE sqli SET password = '" + password + "', username = '" + username + "' WHERE id = '" + id + "'";
                    log.info("当前执行数据更新操作:" + sql);
                    rowsAffected = stmt.executeUpdate(sql);
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "Data updated successfully." : "Update failed. User ID does not exist.";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    sql = "SELECT * FROM sqli WHERE id  = " + id;
                    log.info("当前执行数据查询操作:" + sql);
                    // 2024/5/ueditor 这里用户id不存在时 异常处理还是有问题  已解决:忘记return返回响应数据 顺序执行到default中
                    ResultSet rs = stmt.executeQuery(sql);

                    if (!rs.next()) {
                        stmt.close();
                        conn.close();
                        return R.error("User ID does not exist.");
                    }

                    // 用户ID存在，继续处理查询结果
                    String user = rs.getString("username");
                    String pass = rs.getString("password");

                    message = "Query succeeded. Username: " + user + " Password: " + pass;

                    stmt.close();
                    conn.close();
                    return R.ok(message);
                default:
                    return R.error("Invalid type field. Transport data is abnormal. Please check it.");
            }

        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    /**
     * 在执行DML操作时 上述步骤都会重复出现(重复建立、释放连接) 为了简化重复逻辑 提供代码可维护性
     * 后续发展使用ORM(Object Relational Mapping 对象-关系映射)框架来封装以上重复代码(使用数据库连接池、缓存等技术)
     * 实现对象模型、关系模型之间的转换 ORM框架的核心功能：根据配置配置文件or注解) 实现对象模型、关系模型之间的映射
     * 常用ORM框架：Hibernate、MyBatis、JPA
     */

    @ApiOperation(value = "漏洞场景：JDBC-预编译拼接", notes = "虽然使用了 conn.prepareStatement(sql) 创建了一个 PreparedStatement 对象，但在执行 stmt.executeUpdate(sql) 时，却是传递了完整的 SQL 语句作为参数，而不是使用了预编译的功能")
    @GetMapping("/vul2")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    public R vul2(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        {
            String sql = "";
            try {
                Class.forName("com.mysql.cj.jdbc.Driver");
                Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
                PreparedStatement stmt;
                int rowsAffected;
                String message;
                switch (type) {
                    case "add":
                        sql = "INSERT INTO sqli (username, password) VALUES ('" + username + "', '" + password + "')";
                        log.info("当前执行数据插入操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "Data inserted successfully. username:" + username + "; password:" + password : "Data insertion failed.";
                        log.info(message);
                        return R.ok(message);
                    case "delete":
                        sql = "DELETE FROM sqli WHERE id = '" + id + "'";
                        log.info("当前执行数据删除操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "Data deleted successfully." : "Delete failed. User ID: " + id + " does not exist.";
                        log.info(message);
                        return R.ok(message);
                    case "update":
                        sql = "UPDATE sqli SET username = '" + username + "', password = '" + password + "' WHERE id = '" + id + "'";
                        log.info("当前执行数据更新操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "Data updated successfully." : "Update failed. User ID does not exist.";
                        log.info(message);
                        return R.ok(message);
                    case "select":
                        sql = "SELECT * FROM sqli WHERE id  = " + id;
                        log.info("当前执行数据查询操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        ResultSet rs = stmt.executeQuery(sql);
                        if (!rs.next()) {
                            stmt.close();
                            conn.close();
                            return R.error("User ID does not exist.");
                        }
                        String user = rs.getString("username");
                        String pass = rs.getString("password");
                        stmt.close();
                        conn.close();
                        message = "Query succeeded. Username: " + user + " Password: " + pass;

                        return R.ok(message);
                    default:
                        return R.error("Invalid type field. Transport data is abnormal. Please check it.");
                }
            } catch (Exception e) {
                log.error(e.toString());
                return R.error(e.toString());
            }
        }
    }

    @ApiOperation(value = "漏洞场景：JdbcTemplate-SQL语句拼接", notes = "JDBCTemplate是Spring对JDBC的封装，底层实现实际上还是JDBC")
    @GetMapping("/vul3")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    public R vul3(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        String sql = "";
        try {
            DriverManagerDataSource dataSource = new DriverManagerDataSource();
            dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
            dataSource.setUrl(dbUrl);
            dataSource.setUsername(dbUser);
            dataSource.setPassword(dbPass);
            JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);

            int rowsAffected;
            String message;
            switch (type) {
                case "add":
                    sql = "INSERT INTO sqli (username, password) VALUES ('" + username + "', '" + password + "')";
                    log.info("当前执行数据插入操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql);        //Spring的JdbcTemplate会自动管理连接的获取和释放，不需要手动关闭连接
                    message = (rowsAffected > 0) ? "Data inserted successfully. username:" + username + "; password:" + password : "Data insertion failed.";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    sql = "DELETE FROM sqli WHERE id = '" + id + "'";
                    log.info("当前执行数据删除操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql);
                    message = (rowsAffected > 0) ? "Data deleted successfully." : "Delete failed. User ID: " + id + " does not exist.";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    sql = "UPDATE sqli SET username = '" + username + "', password = '" + password + "' WHERE id = '" + id + "'";
                    log.info("当前执行数据更新操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql);
                    message = (rowsAffected > 0) ? "Data updated successfully." : "Update failed. User ID does not exist.";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    sql = "SELECT * FROM sqli WHERE id  = " + id;
                    List<Map<String, Object>> resultList = jdbctemplate.queryForList(sql);
                    if (resultList.isEmpty()) {
                        return R.error("User ID does not exist.");
                    }
                    log.info(resultList.toString());
                    message = "Query succeeded. Found " + resultList.size() + " records " + JSONUtil.toJsonStr(resultList);
                    return R.ok(message);

                default:
                    return R.error("Invalid type field. Transport data is abnormal. Please check it.");
            }

        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "安全代码：JDBC预编译", notes = "采用预编译的方法，使用?占位，也叫参数化的SQL")
    @GetMapping("/safe1")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    public R safe1(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        String sql = "";
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");

            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
            PreparedStatement stmt;
            int rowsAffected;
            String message;
            switch (type) {
                case "add":
                    sql = "INSERT INTO sqli (username, password) VALUES (?, ?)";   // 这里可以看到使用了?占位符 sql语句和参数进行分离
                    log.info("当前执行数据插入操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, username);                // 参数化处理
                    stmt.setString(2, password);

                    rowsAffected = stmt.executeUpdate();                    // 使用预编译时 不需要传递sql语句
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "Data inserted successfully. username:" + username + "; password:" + password : "Data insertion failed.";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    sql = "DELETE FROM sqli WHERE id = ?";
                    log.info("当前执行数据删除操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, id);

                    rowsAffected = stmt.executeUpdate();
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "Data deleted successfully." : "Delete failed. User ID: " + id + " does not exist.";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    sql = "UPDATE sqli SET username = ?, password = ? WHERE id = ?";
                    log.info("当前执行数据更新操作: " + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, username);
                    stmt.setString(2, password);
                    stmt.setString(3, id);

                    rowsAffected = stmt.executeUpdate();
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "Data updated successfully." : "Update failed. User ID does not exist.";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    sql = "SELECT * FROM sqli WHERE id  = ?";
                    log.info("当前执行数据查询操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, id);
                    ResultSet rs = stmt.executeQuery();
                    if (!rs.next()) {
                        stmt.close();
                        conn.close();
                        return R.error("User ID does not exist.");
                    }
                    String user = rs.getString("username");
                    String pass = rs.getString("password");
                    stmt.close();
                    conn.close();
                    message = "Query succeeded. Username: " + user + " Password: " + pass;
                    return R.ok(message);
                default:
                    return R.error("Invalid type field. Transport data is abnormal. Please check it.");
            }

        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "安全代码：JdbcTemplate参数绑定", notes = "JdbcTemplate通过占位符和参数绑定分离SQL结构与参数值，可在常规DML场景中有效防止SQL注入")
    @GetMapping("/safe2")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    public R safe2(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        String sql = "";
        try {
            DriverManagerDataSource dataSource = new DriverManagerDataSource();
            dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
            dataSource.setUrl(dbUrl);
            dataSource.setUsername(dbUser);
            dataSource.setPassword(dbPass);
            JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);

            int rowsAffected;
            String message;
            switch (type) {
                case "add":
                    sql = "INSERT INTO sqli (username, password) VALUES (?,?)";
                    log.info("当前执行数据插入操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql, username, password);
                    message = (rowsAffected > 0) ? "Data inserted successfully. username:" + username + "; password:" + password : "Data insertion failed.";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    sql = "DELETE FROM sqli WHERE id = ?";
                    log.info("当前执行数据删除操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql, id);
                    message = (rowsAffected > 0) ? "Data deleted successfully." : "Delete failed. User ID: " + id + " does not exist.";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    sql = "UPDATE sqli SET username = ?, password = ? WHERE id = ?";
                    log.info("当前执行数据更新操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql, username,password,id);
                    message = (rowsAffected > 0) ? "Data updated successfully." : "Update failed. User ID does not exist.";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    sql = "SELECT * FROM sqli WHERE id  = ?";
                    log.info("当前执行数据查询操作:" + sql);
                    Map<String, Object> stringObjectMap;
                    try {
                        stringObjectMap = jdbctemplate.queryForMap(sql, id);
                    } catch (EmptyResultDataAccessException e) {
                        return R.error("User ID does not exist.");
                    }
                    String user = (String) stringObjectMap.get("username");
                    String pass = (String) stringObjectMap.get("password");

                    message = "Query succeeded. Username: " + user + " Password: " + pass;
                    return R.ok(message);
                default:
                    return R.error("Invalid type field. Transport data is abnormal. Please check it.");
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "辅助方案：自定义黑名单-用户输入过滤", notes = "黑名单只能作为辅助检测或拦截，不应替代参数化查询。遗漏关键字、编码绕过、语法变形都可能导致绕过。")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    @GetMapping("/safe3")
    public R safe3(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        String sql = "";
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
            Statement stmt = conn.createStatement();
            int rowsAffected;
            String message;
            switch (type) {
                case "add":
                    if (checkUserInput.checkSqlBlackList(username) || checkUserInput.checkSqlBlackList(password)) {
                        log.warn("Blacklist detected an illegal SQL injection payload.");
                        return R.error("Blacklist detected an illegal SQL injection payload.");
                    } else {
                        sql = "INSERT INTO sqli (username, password) VALUES ('" + username + "', '" + password + "')";
                        log.info("当前执行数据插入操作:" + sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "Data inserted successfully. username:" + username + "; password:" + password : "Data insertion failed.";
                        log.info(message);
                        return R.ok(message);
                    }
                case "delete":
                    if (checkUserInput.checkSqlBlackList(id)) {
                        log.warn("Blacklist detected an illegal SQL injection payload.");
                        return R.error("Blacklist detected an illegal SQL injection payload.");
                    } else {
                        sql = "DELETE FROM sqli WHERE id = '" + id + "'";
                        log.info("当前执行数据删除操作:" + sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "Data deleted successfully." : "Delete failed. User ID: " + id + " does not exist.";
                        log.info(message);
                        return R.ok(message);
                    }
                case "update":
                    if (checkUserInput.checkSqlBlackList(id) || checkUserInput.checkSqlBlackList(username) || checkUserInput.checkSqlBlackList(password)) {
                        log.warn("Blacklist detected an illegal SQL injection payload.");
                        return R.error("Blacklist detected an illegal SQL injection payload.");
                    } else {
                        sql = "UPDATE sqli SET password = '" + password + "', username = '" + username + "' WHERE id = '" + id + "'";
                        log.info("当前执行数据更新操作:" + sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "Data updated successfully." : "Update failed. User ID does not exist.";
                        log.info(message);
                        return R.ok(message);
                    }
                case "select":
                    if (checkUserInput.checkSqlBlackList(id)) {
                        log.warn("Blacklist detected an illegal SQL injection payload.");
                        return R.error("Blacklist detected an illegal SQL injection payload.");
                    } else {
                        sql = "SELECT * FROM sqli WHERE id  = " + id;
                        log.info("当前执行数据查询操作:" + sql);
                        ResultSet rs = stmt.executeQuery(sql);
                        if (!rs.next()) {
                            stmt.close();
                            conn.close();
                            return R.ok("User ID does not exist.");
                        }
                        String user = rs.getString("username");
                        String pass = rs.getString("password");
                        message = "Query succeeded. Username: " + user + " Password: " + pass;

                        stmt.close();
                        conn.close();
                        return R.ok(message);
                    }
                default:
                    return R.error("Invalid type field. Transport data is abnormal. Please check it.");
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    // 对用户输入进行校验后 同样也可以避免SQL注入 后续在MyBatis模块中 将通过validation模块 利用Spring框架提供的注解来对请求参数进行验证，从而确保它们满足特定的条件
    @ApiOperation(value = "安全代码：数据类型-用户请求参数校验", notes = "强制类型转换 对用户请求参数进行校验")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    @GetMapping("/safe4")
    public R safe4(
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id) {
        String sql = "";
        try {
            if (id == null || id.trim().isEmpty()) {
                return R.error("Please enter user ID.");
            }
            Integer userId;
            try {
                userId = Integer.valueOf(id);
            } catch (NumberFormatException e) {
                return R.error("User ID must be an integer.");
            }
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
            Statement stmt = conn.createStatement();
            String message;
            message = checkUserInput.checkUser(userId);
            if (!message.isEmpty()) return R.error(message);
            sql = "SELECT * FROM sqli WHERE id  = " + userId;
            log.info("当前执行数据查询操作:" + sql);
            ResultSet rs = stmt.executeQuery(sql);
            if (!rs.next()) {
                stmt.close();
                conn.close();
                return R.ok("User ID does not exist.");
            }
            String user = rs.getString("username");
            String pass = rs.getString("password");
            message = "Query succeeded. Username: " + user + " Password: " + pass;
            stmt.close();
            conn.close();
            return R.ok(message);

        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "辅助方案：ESAPI encodeForSQL", notes = "encodeForSQL是历史方案或特定数据库Codec场景下的补充手段，不推荐作为SQL注入的首选修复。优先使用参数化查询。")
    @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class)
    @GetMapping("/safe5")
    @ResponseBody
    public R safe5(@ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id) {
        try {
            Codec<Character> oracleCodec = new OracleCodec();
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);

            Statement stmt = conn.createStatement();
            // encodeForSQL是历史方案或特定数据库Codec场景下的补充手段，优先使用参数化查询。
            String sql = "select * from sqli where id = '" + ESAPI.encoder().encodeForSQL(oracleCodec, id) + "'";
//            String sql = "select * from sqli where id = '" + id + "'";
            log.info("当前执行数据查询操作:" + sql);
            ResultSet rs = stmt.executeQuery(sql);
            if (!rs.next()) {
                stmt.close();
                conn.close();
                return R.error("User ID does not exist.");
            }

            // 用户ID存在，继续处理查询结果
            String user = rs.getString("username");
            String pass = rs.getString("password");
            String message = "Query succeeded. Username: " + user + " Password: " + pass;

            stmt.close();
            conn.close();
            return R.ok(message);
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    /*
        预编译功能跟MySQL版本及 MySQL Connector/J（JDBC驱动）版本都有关，首先MySQL服务端是在4.1版本之后才开始支持预编译的，之后的版本都默认支持预编译，
        并且预编译还与 MySQL Connector/J（JDBC驱动）的版本有关， Connector/J 5.0.5之前的版本默认支持预编译， Connector/J 5.0.5之后的版本默认不支持预编译，
         所以我们用的Connector/J 5.0.5驱动以后版本的话默认都是没有打开预编译的 （如果需要打开预编译，需要配置 useServerPrepStmts 参数）
     */
    @ApiOperation(value = "特殊场景：使用prepareStatement时，order by下的sql注入问题", notes = "占位符只能绑定值，不能绑定列名、表名、关键字、排序方向等SQL结构。ORDER BY动态字段应使用枚举映射或白名单。")
    @GetMapping("/special1-OrderBy")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "field", value = "字段名", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    public R special1OrderBy(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "field", value = "字段名") @RequestParam(required = false) String field
    ) {
        log.info("根据" + field + "字段排序，默认升序");
        String sql = "";
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
            JSONObject result;
            PreparedStatement preparedStatement;
            ResultSet rs;
            switch (type) {
                case "raw":
                    sql = "SELECT * FROM sqli ORDER BY " + field;
                    log.info("当前执行数据排序操作：" + sql + " 参数：" + field);
                    preparedStatement = conn.prepareStatement(sql);
                    rs = preparedStatement.executeQuery();

                    JSONArray jsonArray = new JSONArray();
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("username");
                        String pass = rs.getString("password");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject);
                    }
                    return R.ok(jsonArray.toString());

                case "prepareStatement":
                    // 占位符只能绑定值，不能把用户输入变成列名。这里不会按传入字段排序。
                    sql = "select * from sqli order by ?";
                    log.info("当前执行数据排序操作：" + sql + " 参数：" + field);
                    preparedStatement = conn.prepareStatement(sql);
                    preparedStatement.setString(1, field);
                    rs = preparedStatement.executeQuery();

                    jsonArray = new JSONArray();
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("username");
                        String pass = rs.getString("password");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject);
                    }
                    return R.ok(jsonArray.toString());
                case "writeList":
                    if (!checkUserInput.checkSqlWhiteList(field)) {
                        log.error("Invalid field.field:" + field);
                        return R.error("Invalid field.");
                    }
                    sql = "SELECT * FROM sqli ORDER BY " + field;
                    log.info("当前执行数据排序操作：" + sql + " 参数：" + field);
                    preparedStatement = conn.prepareStatement(sql);
                    rs = preparedStatement.executeQuery();

                    jsonArray = new JSONArray();
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("username");
                        String pass = rs.getString("password");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject);
                    }
                    return R.ok(jsonArray.toString());
                default:
                    return R.error("Invalid type field. Transport data is abnormal. Please check it.");
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "特殊场景：使用%和模糊查询-like")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "keyword", value = "关键词", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    @GetMapping("/special2-Like")
    public R special2Like(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "keyword", value = "关键词") @RequestParam(required = false) String keyword
    ) {
        log.info("正在查找关键词：" + keyword);
        String sql = "";
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
            Statement stmt = conn.createStatement();
            PreparedStatement preparedStatement;
            ResultSet rs;
            switch (type) {
                case "raw":                                                 // 查询语句拼接
                    sql = "SELECT * FROM sqli WHERE username LIKE '%" + keyword + "%'";
//                    sql = "SELECT * FROM sqli WHERE username LIKE concat('%', '" + keyword + "', '%')";
                    log.info("当前执行数据查询操作:" + sql);
                    rs = stmt.executeQuery(sql);
//                    if (!rs.next()) {
//                        stmt.close();
//                        conn.close();
//                        return R.error("No matching user information.");
//                    }

                    JSONArray jsonArray = new JSONArray();
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("username");
                        String pass = rs.getString("password");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject);
                    }
                    stmt.close();
                    conn.close();
                    return R.ok(jsonArray.toString());
                case "prepareStatement":                                         // 使用预编译
                    sql = "SELECT * FROM sqli WHERE username LIKE ?";
                    log.info("执行的sql语句：" + sql);
                    preparedStatement = conn.prepareStatement(sql);
                    preparedStatement.setString(1, "%" + keyword + "%");
                    rs = preparedStatement.executeQuery();

                    jsonArray = new JSONArray();
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("username");
                        String pass = rs.getString("password");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject);
                    }
                    return R.ok(jsonArray.toString());
                default:
                    return R.error("Invalid type field. Transport data is abnormal. Please check it.");
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "特殊场景：Limit注入")
    @GetMapping("/special3-Limit")
    @ResponseBody
    public R special3Limit(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "size", value = "数量") @RequestParam(required = false) String size
    ) {
        log.info("正在查找关键词：" + size);
        String sql = "";
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
            Statement stmt = conn.createStatement();
            PreparedStatement preparedStatement;
            ResultSet rs;
            switch (type) {
                case "raw":
                    sql = "SELECT * FROM sqli ORDER BY id DESC LIMIT " + size;
                    log.info("当前执行数据查询操作:" + sql);
                    rs = stmt.executeQuery(sql);
                    JSONArray jsonArray = new JSONArray();
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("username");
                        String pass = rs.getString("password");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject);
                    }
                    stmt.close();
                    conn.close();
                    if (jsonArray.isEmpty()) {
                        return R.error("No matching user information.");
                    }
                    return R.ok(jsonArray.toString());
                case "prepareStatement":                                         // 使用预编译
                    sql = "SELECT * FROM sqli ORDER BY id DESC LIMIT ?";
                    log.info("执行的sql语句：" + sql);
                    int limitSize;
                    try {
                        limitSize = Integer.parseInt(size);
                    } catch (NumberFormatException e) {
                        return R.error("Size must be an integer.");
                    }
                    preparedStatement = conn.prepareStatement(sql);
                    preparedStatement.setInt(1, limitSize);
                    rs = preparedStatement.executeQuery();

                    jsonArray = new JSONArray();
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("username");
                        String pass = rs.getString("password");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject);
                    }
                    return R.ok(jsonArray.toString());
                default:
                    return R.error("Invalid type field. Transport data is abnormal. Please check it.");
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "特殊场景：二次SQL注入", notes = "第一次使用参数化写入恶意数据，第二次从数据库取出该数据并拼接进SQL时触发注入。")
    @GetMapping("/special4-SecondOrder")
    @ResponseBody
    public R special4SecondOrder(
            @ApiParam(name = "type", value = "操作类型：store、trigger、safeTrigger", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password
    ) {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass)) {
                switch (type) {
                    case "store":
                        if (username == null || username.trim().isEmpty()) {
                            return R.error("Username cannot be empty.");
                        }
                        String insertSql = "INSERT INTO sqli (username, password) VALUES (?, ?)";
                        log.info("二次注入第一步，参数化写入数据: {}", insertSql);
                        try (PreparedStatement preparedStatement = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                            preparedStatement.setString(1, username);
                            preparedStatement.setString(2, password);
                            int rowsAffected = preparedStatement.executeUpdate();
                            String newId = "";
                            try (ResultSet generatedKeys = preparedStatement.getGeneratedKeys()) {
                                if (generatedKeys.next()) {
                                    newId = generatedKeys.getString(1);
                                }
                            }
                            return R.ok("Data written successfully. Affected rows: " + rowsAffected + ", new user ID: " + newId + ". Use this ID in the next step to trigger the second query.");
                        }
                    case "trigger":
                        return queryByStoredUsername(conn, id, false);
                    case "safeTrigger":
                        return queryByStoredUsername(conn, id, true);
                    default:
                        return R.error("Invalid type field. Transport data is abnormal. Please check it.");
                }
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "特殊场景：UNION联合查询回显", notes = "通过UNION SELECT拼接额外查询结果，使数据库名、当前用户等信息进入正常查询回显。")
    @GetMapping("/special5-Union")
    @ResponseBody
    public R special5Union(
            @ApiParam(name = "type", value = "操作类型：raw、prepareStatement", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID或UNION Payload") @RequestParam(required = false) String id
    ) {
        String sql = "";
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass)) {
                ResultSet rs;
                switch (type) {
                    case "raw":
                        sql = "SELECT id, username, password FROM sqli WHERE id = " + id;
                        log.info("当前执行UNION回显查询操作: {}", sql);
                        try (Statement stmt = conn.createStatement()) {
                            rs = stmt.executeQuery(sql);
                            return R.ok(resultSetToJsonArray(rs).toString());
                        }
                    case "prepareStatement":
                        sql = "SELECT id, username, password FROM sqli WHERE id = ?";
                        log.info("当前执行UNION回显安全查询操作: {}", sql);
                        try (PreparedStatement preparedStatement = conn.prepareStatement(sql)) {
                            preparedStatement.setString(1, id);
                            rs = preparedStatement.executeQuery();
                            return R.ok(resultSetToJsonArray(rs).toString());
                        }
                    default:
                        return R.error("Invalid type field. Transport data is abnormal. Please check it.");
                }
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    private R queryByStoredUsername(Connection conn, String id, boolean safe) throws SQLException {
        if (id == null || id.trim().isEmpty()) {
            return R.error("ID cannot be empty.");
        }
        String usernameSql = "SELECT username FROM sqli WHERE id = ?";
        String storedUsername;
        try (PreparedStatement preparedStatement = conn.prepareStatement(usernameSql)) {
            preparedStatement.setString(1, id);
            try (ResultSet rs = preparedStatement.executeQuery()) {
                if (!rs.next()) {
                    return R.error("User ID does not exist.");
                }
                storedUsername = rs.getString("username");
            }
        }

        if (safe) {
            String safeSql = "SELECT id, username, password FROM sqli WHERE username = ?";
            log.info("二次注入安全触发，参数化查询: {} 参数: {}", safeSql, storedUsername);
            try (PreparedStatement preparedStatement = conn.prepareStatement(safeSql)) {
                preparedStatement.setString(1, storedUsername);
                try (ResultSet rs = preparedStatement.executeQuery()) {
                    return R.ok(resultSetToJsonArray(rs).toString());
                }
            }
        }

        String vulSql = "SELECT id, username, password FROM sqli WHERE username = '" + storedUsername + "'";
        log.info("二次注入漏洞触发，拼接查询: {}", vulSql);
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(vulSql)) {
            return R.ok(resultSetToJsonArray(rs).toString());
        }
    }

    private JSONArray resultSetToJsonArray(ResultSet rs) throws SQLException {
        JSONArray jsonArray = new JSONArray();
        while (rs.next()) {
            JSONObject jsonObject = JSONUtil.createObj();
            jsonObject.put("id", rs.getString("id"));
            jsonObject.put("username", rs.getString("username"));
            jsonObject.put("password", rs.getString("password"));
            jsonArray.put(jsonObject);
        }
        return jsonArray;
    }

}
