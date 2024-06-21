package top.whgojp.modules.injection.sqli.controller;

import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.OracleCodec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
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
import java.util.Map;

/**
 * @description sql注入-JDBC原生操作
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/27 21:46
 */
@Api(value = "JdbcController", tags = "SQL注入1-JDBC")
@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/sqli/jdbc")
public class JdbcController {
    @Autowired
    private CheckUserInput checkUserInput;
    Logger log = LoggerFactory.getLogger(JdbcController.class);

    //指定数据库地址、用户名、密码
    @Value("${spring.datasource.url}")
    private String dbUrl;
    @Value("${spring.datasource.username}")
    private String dbUser;
    @Value("${spring.datasource.password}")
    private String dbPass;

    @ApiOperation(value = "漏洞环境：JDBC-原生SQL语句拼接", notes = "原生sql语句动态拼接 参数未进行任何处理")
    @GetMapping("/a-vul1-raw-joint")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),     // 注意这里id是String类型
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R vul1RawJoint(
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
                    sql = "INSERT INTO users (user, pass) VALUES ('" + username + "', '" + password + "')"; //这里没有标识id id自增长
                    log.info("当前执行数据插入操作:" + sql);
                    //通过Statement对象执行SQL语句，得到ResultSet对象-查询结果集
                    rowsAffected = stmt.executeUpdate(sql);         // 这里注意一下 insert、update、delete 语句应使用executeUpdate()
                    //关闭ResultSet结果集 Statement对象 以及数据库Connection对象 释放资源
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "数据插入成功 username:" + username + ";password:" + password : "数据插入失败";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    sql = "DELETE FROM users WHERE id = '" + id + "'";
                    log.info("当前执行数据删除操作:" + sql);
                    rowsAffected = stmt.executeUpdate(sql);
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "数据删除成功" : "数据删除失败 用户ID:" + id + " 不存在!";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    message = checkUserInput.checkUser(username, password);
                    if (!message.isEmpty()) return R.error(message);
                    sql = "UPDATE users SET pass = '" + password + "', user = '" + username + "' WHERE id = '" + id + "'";
                    log.info("当前执行数据更新操作:" + sql);
                    rowsAffected = stmt.executeUpdate(sql);
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "数据更新成功" : "数据更新失败 用户ID不存在!";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    sql = "SELECT * FROM users WHERE id  = " + id;
                    log.info("当前执行数据查询操作:" + sql);
                    // 2024/5/1 这里用户id不存在时 异常处理还是有问题  已解决:忘记return返回响应数据 顺序执行到default中
                    ResultSet rs = stmt.executeQuery(sql);

                    if (!rs.next()) {
                        stmt.close();
                        conn.close();
                        return R.error("用户ID不存在");
                    }

                    // 用户ID存在，继续处理查询结果
                    String user = rs.getString("user");
                    String pass = rs.getString("pass");
                    final JSONObject jsonObject = JSONUtil.createObj();
                    jsonObject.put("username", user);
                    jsonObject.put("password", pass);

                    stmt.close();
                    conn.close();
                    return R.ok(jsonObject);
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
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

    @ApiOperation(value = "漏洞环境：JDBC-预编译拼接", notes = "虽然使用了 conn.prepareStatement(sql) 创建了一个 PreparedStatement 对象，但在执行 stmt.executeUpdate(sql) 时，却是传递了完整的 SQL 语句作为参数，而不是使用了预编译的功能")
    @GetMapping("/a-vul2-prepareStatement-joint")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R vul2prepareStatementJoint(
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
                        sql = "INSERT INTO users (user, pass) VALUES ('" + username + "', '" + password + "')";
                        log.info("当前执行数据插入操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "数据插入成功 username:" + username + ";password:" + password : "数据插入失败";
                        log.info(message);
                        return R.ok(message);
                    case "delete":
                        sql = "DELETE FROM users WHERE id = '" + id + "'";
                        log.info("当前执行数据删除操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "数据删除成功" : "数据删除失败 用户ID:" + id + " 不存在!";
                        log.info(message);
                        return R.ok(message);
                    case "update":
                        sql = "UPDATE users set pass = '" + password + "' where id = '" + id + "'";
                        log.info("当前执行数据更新操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "数据更新成功" : "数据更新失败 用户ID不存在!";
                        log.info(message);
                        return R.ok(message);
                    case "select":
                        sql = "SELECT * FROM users WHERE id  = " + id;
                        log.info("当前执行数据查询操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        ResultSet rs = stmt.executeQuery(sql);
                        if (!rs.next()) {
                            stmt.close();
                            conn.close();
                            return R.error("用户ID不存在");
                        }
                        String user = rs.getString("user");
                        String pass = rs.getString("pass");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);

                        stmt.close();
                        conn.close();
                        return R.ok(jsonObject);
                    default:
                        return R.error("type字段有误：传输数据异常,请检查^_^");
                }
            } catch (Exception e) {
                log.error(e.toString());
                return R.error(e.toString());
            }
        }
    }

    @ApiOperation(value = "漏洞环境：JdbcTemplate-SQL语句拼接", notes = "JDBCTemplate是Spring对JDBC的封装，底层实现实际上还是JDBC")
    @GetMapping("/a-vul3-JdbcTemplate-joint")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R vul3JdbcTemplateJoint(
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
                    sql = "INSERT INTO users (user, pass) VALUES ('" + username + "', '" + password + "')";
                    log.info("当前执行数据插入操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql);        //Spring的JdbcTemplate会自动管理连接的获取和释放，不需要手动关闭连接
                    message = (rowsAffected > 0) ? "数据插入成功 username:" + username + ";password:" + password : "数据插入失败";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    sql = "DELETE FROM users WHERE id = '" + id + "'";
                    log.info("当前执行数据删除操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql);
                    message = (rowsAffected > 0) ? "数据删除成功" : "数据删除失败 用户ID:" + id + " 不存在!";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    sql = "UPDATE users set pass = '" + password + "' where id = '" + id + "'";
                    log.info("当前执行数据更新操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql);
                    message = (rowsAffected > 0) ? "数据更新成功" : "数据更新失败 用户ID不存在!";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    sql = "SELECT * FROM users WHERE id  = " + id;
                    Map<String, Object> stringObjectMap;
                    try {
                        stringObjectMap = jdbctemplate.queryForMap(sql);
                    } catch (EmptyResultDataAccessException e) {
                        return R.error("用户ID不存在");
                    }
                    final JSONObject jsonObject = JSONUtil.createObj();
                    jsonObject.put("result", stringObjectMap);
                    log.info(stringObjectMap.toString());
                    return R.ok(jsonObject);

                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }

        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "安全代码：JDBC预编译", notes = "采用预编译的方法，使用?占位，也叫参数化的SQL")
    @GetMapping("/b-safe1-PrepareStatement-Parametric")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safe1PrepareStatementParametric(
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
                    sql = "INSERT INTO users (user, pass) VALUES (?, ?)";   // 这里可以看到使用了?占位符 sql语句和参数进行分离
                    log.info("当前执行数据插入操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, username);                // 参数化处理
                    stmt.setString(2, password);

                    rowsAffected = stmt.executeUpdate();                    // 使用预编译时 不需要传递sql语句
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "数据插入成功 username:" + username + ";password:" + password : "数据插入失败";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    sql = "DELETE FROM users WHERE id = ?";
                    log.info("当前执行数据删除操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, id);

                    rowsAffected = stmt.executeUpdate();
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "数据删除成功" : "数据删除失败 用户ID:" + id + " 不存在!";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    sql = "UPDATE users set pass = ? where id = ?";
                    log.info("当前执行数据更新操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, password);
                    stmt.setString(2, id);

                    rowsAffected = stmt.executeUpdate();
                    stmt.close();
                    conn.close();
                    message = (rowsAffected > 0) ? "数据更新成功" : "数据更新失败 用户ID不存在!";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    sql = "SELECT * FROM users WHERE id  = ?";
                    log.info("当前执行数据查询操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, id);
                    ResultSet rs = stmt.executeQuery();
                    if (!rs.next()) {
                        stmt.close();
                        conn.close();
                        return R.error("用户ID不存在");
                    }
                    String user = rs.getString("user");
                    String pass = rs.getString("pass");
                    final JSONObject jsonObject = JSONUtil.createObj();
                    jsonObject.put("username", user);
                    jsonObject.put("password", pass);

                    stmt.close();
                    conn.close();
                    return R.ok(jsonObject);
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }

        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "安全代码：JdbcTemplate预编译", notes = "JDBCTemplate预编译 此时在常规DML场景有效的防止了SQL注入攻击的发生")
    @GetMapping("/b-safe2-JdbcTemplate-PrepareStatement-Parametric")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safe2JdbcTemplatePrepareStatementParametric(
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
                    sql = "INSERT INTO users (user, pass) VALUES (?,?)";
                    log.info("当前执行数据插入操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql, username, password);
                    message = (rowsAffected > 0) ? "数据插入成功 username:" + username + ";password:" + password : "数据插入失败";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    sql = "DELETE FROM users WHERE id = ?";
                    log.info("当前执行数据删除操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql, id);
                    message = (rowsAffected > 0) ? "数据删除成功" : "数据删除失败 用户ID:" + id + " 不存在!";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    sql = "UPDATE users set pass = ? where id = ?";
                    log.info("当前执行数据更新操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql, username, id);
                    message = (rowsAffected > 0) ? "数据更新成功" : "数据更新失败 用户ID不存在!";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    sql = "SELECT * FROM users WHERE id  = ?";
                    log.info("当前执行数据查询操作:" + sql);
                    Map<String, Object> stringObjectMap;
                    try {
                        stringObjectMap = jdbctemplate.queryForMap(sql, id);
                    } catch (EmptyResultDataAccessException e) {
                        return R.error("用户ID不存在");
                    }
                    final JSONObject jsonObject = JSONUtil.createObj();
                    jsonObject.put("result", stringObjectMap);
                    log.info(stringObjectMap.toString());
                    return R.ok(jsonObject);

                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "安全代码：自定义黑名单-用户输入过滤", notes = "检测用户输入是否存在敏感字符：'、;、--、+、,、%、=、>、<、*、(、)、and、or、exeinsert、select、delete、update、count、drop、chr、midmaster、truncate、char、declare")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @GetMapping("/b-safe3-Blacklist-checkSqlBlackList")
    public R safe3BlacklistcheckSqlBlackList(
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
                        log.warn("黑名单检测到非法SQL注入!");
                        return R.error("黑名单检测到非法SQL注入!");
                    } else {
                        sql = "INSERT INTO users (user, pass) VALUES ('" + username + "', '" + password + "')";
                        log.info("当前执行数据插入操作:" + sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "数据插入成功 username:" + username + ";password:" + password : "数据插入失败";
                        log.info(message);
                        return R.ok(message);
                    }
                case "delete":
                    if (checkUserInput.checkSqlBlackList(id)) {
                        log.warn("黑名单检测到非法SQL注入!");
                        return R.error("黑名单检测到非法SQL注入!");
                    } else {
                        sql = "DELETE FROM users WHERE id = '" + id + "'";
                        log.info("当前执行数据删除操作:" + sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "数据删除成功" : "数据删除失败 用户ID:" + id + " 不存在!";
                        log.info(message);
                        return R.ok(message);
                    }
                case "update":
                    if (checkUserInput.checkSqlBlackList(id) || checkUserInput.checkSqlBlackList(username) || checkUserInput.checkSqlBlackList(id)) {
                        log.warn("黑名单检测到非法SQL注入!");
                        return R.error("黑名单检测到非法SQL注入!");
                    } else {
                        sql = "UPDATE users SET pass = '" + password + "', user = '" + username + "' WHERE id = '" + id + "'";
                        log.info("当前执行数据更新操作:" + sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "数据更新成功" : "数据更新失败 用户ID不存在!";
                        log.info(message);
                        return R.ok(message);
                    }
                case "select":
                    if (checkUserInput.checkSqlBlackList(id)) {
                        log.warn("黑名单检测到非法SQL注入!");
                        return R.error("黑名单检测到非法SQL注入!");
                    } else {
                        sql = "SELECT * FROM users WHERE id  = " + id;
                        log.info("当前执行数据查询操作:" + sql);
                        ResultSet rs = stmt.executeQuery(sql);
                        if (!rs.next()) {
                            stmt.close();
                            conn.close();
                            return R.ok("用户ID不存在");
                        }
                        String user = rs.getString("user");
                        String pass = rs.getString("pass");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        stmt.close();
                        conn.close();
                        return R.ok(jsonObject);
                    }
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    // 对用户输入进行校验后 同样也可以避免SQL注入 后续在MyBatis模块中 将通过validation模块 利用Spring框架提供的注解来对请求参数进行验证，从而确保它们满足特定的条件
    @ApiOperation(value = "安全代码：数据类型-用户请求参数校验", notes = "强制类型转换 对用户请求参数进行校验")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "Integer", paramType = "query", dataTypeClass = Integer.class)        // 这里使用了Integer类型
    })
    @GetMapping("/b-safe4-Request-Parameter-Validate")
    public R safe4RequestRarameterValidate(
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) Integer id) {
        String sql = "";
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
            Statement stmt = conn.createStatement();
            String message;
            message = checkUserInput.checkUser(id);
            if (!message.isEmpty()) return R.error(message);
            sql = "SELECT * FROM users WHERE id  = " + id;
            log.info("当前执行数据查询操作:" + sql);
            ResultSet rs = stmt.executeQuery(sql);
            if (!rs.next()) {
                stmt.close();
                conn.close();
                return R.ok("用户ID不存在");
            }
            String user = rs.getString("user");
            String pass = rs.getString("pass");
            final JSONObject jsonObject = JSONUtil.createObj();
            jsonObject.put("username", user);
            jsonObject.put("password", pass);
            stmt.close();
            conn.close();
            return R.ok(jsonObject);

        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "安全代码：Web安全框架-采用ESAPI过滤", notes = "ESAPI提供了多种输入验证API，提供对XSS攻击和SQL注入攻击等的防护")
    @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class)
    @GetMapping("/b-safe4-EASAPI-Filter")
    public R safe4EASAPIFilter(@ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id) {
        try {
            Codec<Character> oracleCodec = new OracleCodec();
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);

            Statement stmt = conn.createStatement();
            // 使用了 Oracle 的编解码器 OracleCodec 和 ESAPI 库来对 ID 进行编码，以防止 SQL 注入攻击。
//            String sql = "select * from users where id = '" + ESAPI.encoder().encodeForSQL(oracleCodec, id) + "'";
            String sql = "select * from users where id = '" + id + "'";
            log.info("当前执行数据查询操作:" + sql);
            ResultSet rs = stmt.executeQuery(sql);
            if (!rs.next()) {
                stmt.close();
                conn.close();
                return R.error("用户ID不存在");
            }

            // 用户ID存在，继续处理查询结果
            String user = rs.getString("user");
            String pass = rs.getString("pass");
            final JSONObject jsonObject = JSONUtil.createObj();
            jsonObject.put("username", user);
            jsonObject.put("password", pass);

            stmt.close();
            conn.close();
            return R.ok(jsonObject);
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
    @ApiOperation(value = "特殊场景：使用prepareStatement时，order by下的sql注入问题", notes = "ORDER BY关键字用于按升序或降序对结果集进行排序。 由于order by后面需要紧跟column_name，而预编译是参数化字符串，而order by后面紧跟字符串就会不支持原有功能 使用默认排序，因此通常防御order by注入需要使用白名单的方式")
    @GetMapping("/special1-OrderBy")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "field", value = "字段名", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
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
                    sql = "SELECT * FROM users ORDER BY " + field;
                    log.info("当前执行数据排序操作：" + sql + " 参数：" + field);
                    preparedStatement = conn.prepareStatement(sql);
                    rs = preparedStatement.executeQuery();

                    JSONArray jsonArray = new JSONArray(); // 创建 JSON 数组来存储所有记录
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("user");
                        String pass = rs.getString("pass");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject); // 将 JSON 对象放入 JSON 数组中
                    }
                    result = new JSONObject(); // 创建结果对象
                    result.put("result", jsonArray); // 将 JSON 数组放入结果对象中
                    return R.ok(result);

                case "prepareStatement":
                    // 可以测试下 预编译没有报错 不过插入语句不生效 默认使用主键升序
                    sql = "select * from users order by ?";
                    log.info("当前执行数据排序操作：" + sql + " 参数：" + field);
                    preparedStatement = conn.prepareStatement(sql);
                    preparedStatement.setString(1, field);
                    rs = preparedStatement.executeQuery();

                    jsonArray = new JSONArray(); // 创建 JSON 数组来存储所有记录
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("user");
                        String pass = rs.getString("pass");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject); // 将 JSON 对象放入 JSON 数组中
                    }
                    result = new JSONObject(); // 创建结果对象
                    result.put("result", jsonArray); // 将 JSON 数组放入结果对象中
                    return R.ok(result);
                case "writeList":
                    sql = "SELECT * FROM users ORDER BY " + field;
                    if (checkUserInput.checkSqlWhiteList(field)) {
                        log.error("field字段不合法！field:" + field);
                        return R.error("field字段不合法！");
                    }
                    log.info("当前执行数据排序操作：" + sql + " 参数：" + field);
                    preparedStatement = conn.prepareStatement(sql);
                    rs = preparedStatement.executeQuery();

                    jsonArray = new JSONArray(); // 创建 JSON 数组来存储所有记录
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("user");
                        String pass = rs.getString("pass");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject); // 将 JSON 对象放入 JSON 数组中
                    }
                    result = new JSONObject(); // 创建结果对象
                    result.put("result", jsonArray); // 将 JSON 数组放入结果对象中
                    return R.ok(result);
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
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
    @GetMapping("/special2-Like")
    public R special2Like(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "keyword", value = "关键词") @RequestParam(required = false) String keyword
    ) {
        log.info("正在查找关键词："+keyword);
        String sql = "";
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
            JSONObject result;
            PreparedStatement preparedStatement;
            ResultSet rs;
            switch (type) {
                case "inside":
                    sql = "SELECT * FROM users WHERE user LIKE '%?%'";
                    preparedStatement = conn.prepareStatement(sql);
                    preparedStatement.setString(1, keyword);
                    rs = preparedStatement.executeQuery();

                    JSONArray jsonArray = new JSONArray(); // 创建 JSON 数组来存储所有记录
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("user");
                        String pass = rs.getString("pass");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject); // 将 JSON 对象放入 JSON 数组中
                    }
                    result = new JSONObject(); // 创建结果对象
                    result.put("result", jsonArray); // 将 JSON 数组放入结果对象中
                    return R.ok(result);

                case "outside":
                    sql = "SELECT * FROM users WHERE user LIKE ?";
                    preparedStatement = conn.prepareStatement(sql);
                    preparedStatement.setString(1, "%"+keyword+"%");
                    rs = preparedStatement.executeQuery();

                    jsonArray = new JSONArray(); // 创建 JSON 数组来存储所有记录
                    while (rs.next()) {
                        String id = rs.getString("id");
                        String user = rs.getString("user");
                        String pass = rs.getString("pass");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", id);
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        jsonArray.put(jsonObject); // 将 JSON 对象放入 JSON 数组中
                    }
                    result = new JSONObject(); // 创建结果对象
                    result.put("result", jsonArray); // 将 JSON 数组放入结果对象中
                    return R.ok(result);
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "特殊场景：Limit注入")
    @GetMapping("/special3")
    public R special4() {
        return R.ok();
    }

    @ApiOperation(value = "特殊场景：Update注入")
    @GetMapping("/special4")
    public R special5() {
        return R.ok();
    }
}
