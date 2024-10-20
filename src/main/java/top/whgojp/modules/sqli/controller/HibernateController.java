package top.whgojp.modules.sqli.controller;

import io.swagger.annotations.*;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;
import top.whgojp.modules.sqli.entity.Hsqli;
import top.whgojp.modules.sqli.entity.Sqli;
import top.whgojp.modules.system.entity.User;

import javax.transaction.SystemException;
import javax.transaction.Transaction;
import javax.transaction.Transactional;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

/**
 * @description ORM框架-Hibernate下的sql注入问题
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/28 10:13
 */
@Api(value = "HibernateController",tags = "SQL注入-Hibernate")
@Slf4j
@Controller
@RequestMapping("/sqli/hibernate")
public class HibernateController {
    @RequestMapping("")
    public String sqliJdbc(){
        return "vul/sqli/hibernate";
    }

    @Autowired
    private SessionFactory sessionFactory; // 依赖注入 Hibernate SessionFactory

    @ApiOperation(value = "漏洞环境：Hibernate-原生SQL语句拼接", notes = "演示SQL注入风险，模拟原生SQL语句动态拼接，参数未进行任何处理，存在严重安全风险")
    @GetMapping("/vul")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    @Transactional // 使用Spring的事务管理
    public R vul(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {

        Session session = sessionFactory.getCurrentSession(); // 获取当前 Session
        String message;

        try {
            switch (type) {
                case "add":  // 插入操作，存在SQL注入风险点
                    // 新建用户对象并设置属性（未对输入进行任何过滤）
                    Hsqli newHsqli = new Hsqli();
                    newHsqli.setUsername(username);
                    newHsqli.setPassword(password);

                    // 直接保存对象到数据库
                    session.save(newHsqli);
                    message = "数据插入成功 username:" + username + " password:" + password; // 直接拼接输出
                    log.info(message);
                    return R.ok(message);

                case "delete":  // 删除操作，注意此处可能引发SQL注入
                    Hsqli deleteHsqli = session.get(Hsqli.class, Long.parseLong(id)); // 使用用户传入的id（未过滤）
                    if (deleteHsqli != null) {
                        session.delete(deleteHsqli);
                        message = "数据删除成功";
                    } else {
                        message = "数据删除失败 用户ID:" + id + " 不存在!";
                    }
                    log.info(message);
                    return R.ok(message);

                case "update":  // 更新操作，存在SQL注入风险点
                    Hsqli updateHsqli = session.get(Hsqli.class, Long.parseLong(id)); // 使用用户输入的id
                    if (updateHsqli != null) {
                        // 设置更新后的值（未对输入值进行过滤或校验）
                        updateHsqli.setUsername(username);
                        updateHsqli.setPassword(password);
                        session.update(updateHsqli);
                        message = "数据更新成功";
                    } else {
                        message = "数据更新失败 用户ID不存在!";
                    }
                    log.info(message);
                    return R.ok(message);

                case "select":  // 查询操作，可能通过ID引入SQL注入
                    Hsqli selectHsqli = session.get(Hsqli.class, Long.parseLong(id)); // 使用传入ID直接查询
                    if (selectHsqli != null) {
                        message = "查询成功，用户名：" + selectHsqli.getUsername() + " 密码：" + selectHsqli.getPassword();
                    } else {
                        message = "用户ID不存在";
                    }
                    log.info(message);
                    return R.ok(message);

                default:
                    // 当type字段未匹配时，返回错误信息
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }
        } catch (NumberFormatException e) {
            log.error("ID格式错误：" + e.getMessage());
            return R.error("ID格式错误：" + e.getMessage());
        } catch (Exception e) {
            log.error("操作失败：" + e.toString());
            return R.error(e.toString());
        }
    }




}
