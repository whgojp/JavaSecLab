package top.whgojp.modules.sqli.controller;

import io.swagger.annotations.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.hibernate5.HibernateTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;
import top.whgojp.modules.sqli.entity.Sqli;

import java.util.List;

/**
 * @description ORM框架-Hibernate下的sql注入问题
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/28 10:13
 */
@Api(value = "HibernateController", tags = "SQL注入-Hibernate")
@Slf4j
@Controller
@RequestMapping("/sqli/hibernate")
public class HibernateController {
    @RequestMapping("")
    public String sqliHibernate() {
        return "vul/sqli/hibernate";
    }

    @Autowired(required = true)
    private HibernateTemplate hibernateTemplate;
    String message = "";

    @RequestMapping("/vul1")
    @ResponseBody
    @ApiOperation(value = "原生SQL注入场景")
    @Transactional(rollbackFor = Exception.class)
    public R vul1(@RequestParam String username) {
        try {
            String sql = "SELECT * FROM sqli WHERE username = '" + username + "'";
            List<Object[]> results = hibernateTemplate.execute(session -> 
                session.createNativeQuery(sql)
                    .addScalar("id", org.hibernate.type.IntegerType.INSTANCE)
                    .addScalar("username", org.hibernate.type.StringType.INSTANCE)
                    .addScalar("password", org.hibernate.type.StringType.INSTANCE)
                    .list()
            );
            if (results == null || results.isEmpty()) {
                return R.error("未找到记录");
            }
            StringBuilder sb = new StringBuilder();
            sb.append("查询成功，找到 ").append(results.size()).append(" 条记录\n");
            for (Object[] row : results) {
                sb.append("ID: ").append(row[0])
                  .append(", 用户名: ").append(row[1])
                  .append(", 密码: ").append(row[2])
                  .append("\n");
            }
            message = sb.toString();
            log.info(message);
            return R.ok(message);
        } catch (Exception e) {
            String errorMsg = e.getMessage();
            log.error("查询失败: {}", errorMsg, e);
            return R.error(errorMsg);
        }
    }

    @RequestMapping("/vul2")
    @ResponseBody
    @ApiOperation(value = "HQL注入场景")
    @Transactional(rollbackFor = Exception.class)
    public R vul2(@RequestParam String username) {
        try {
            String hql = "FROM Sqli WHERE username = '" + username + "'";
            List<Sqli> results = hibernateTemplate.execute(session -> 
                session.createQuery(hql).list()
            );
            if (results == null || results.isEmpty()) {
                return R.error("未找到记录");
            }
            StringBuilder sb = new StringBuilder();
            sb.append("查询成功，找到 ").append(results.size()).append(" 条记录\n");
            for (Sqli sqli : results) {
                sb.append("ID: ").append(sqli.getId())
                  .append(", 用户名: ").append(sqli.getUsername())
                  .append(", 密码: ").append(sqli.getPassword())
                  .append("\n");
            }
            message = sb.toString();
            log.info(message);
            return R.ok(message);
        } catch (Exception e) {
            String errorMsg = e.getMessage();
            log.error("查询失败: {}", errorMsg, e);
            return R.error(errorMsg);
        }
    }

    @RequestMapping("/safe")
    @ResponseBody
    @ApiOperation(value = "安全查询场景")
    @Transactional(rollbackFor = Exception.class)
    public R safe(@RequestParam String username) {
        try {
            String hql = "FROM Sqli WHERE username = :username";
            List<Sqli> results = hibernateTemplate.execute(session -> 
                session.createQuery(hql)
                    .setParameter("username", username)
                    .list()
            );
            if (results == null || results.isEmpty()) {
                return R.error("未找到记录");
            }
            StringBuilder sb = new StringBuilder();
            sb.append("查询成功，找到 ").append(results.size()).append(" 条记录\n");
            for (Sqli sqli : results) {
                sb.append("ID: ").append(sqli.getId())
                  .append(", 用户名: ").append(sqli.getUsername())
                  .append(", 密码: ").append(sqli.getPassword())
                  .append("\n");
            }
            message = sb.toString();
            log.info(message);
            return R.ok(message);
        } catch (Exception e) {
            String errorMsg = e.getMessage();
            log.error("查询失败: {}", errorMsg, e);
            return R.error(errorMsg);
        }
    }
}
