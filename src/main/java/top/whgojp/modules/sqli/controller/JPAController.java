package top.whgojp.modules.sqli.controller;

import io.swagger.annotations.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.annotation.AuthIgnore;
import top.whgojp.common.utils.R;
import top.whgojp.modules.sqli.entity.Sqli;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import java.util.List;

/**
 * @description JPA SQL注入漏洞演示
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/28 10:13
 */
@Api(value = "JpaController", tags = "SQL注入-JPA")
@Slf4j
@Controller
@RequestMapping("/sqli/jpa")
public class JPAController {
    @RequestMapping("")
    public String sqliJpa() {
        return "vul/sqli/jpa";
    }

    @PersistenceContext
    private EntityManager entityManager;
    String message = "";

    @RequestMapping("/vul1")
    @ResponseBody
    @AuthIgnore
    @ApiOperation(value = "JPQL注入场景")
    @Transactional(rollbackFor = Exception.class)
    public R vul1(@RequestParam String username) {
        try {
            String jpql = "SELECT s FROM Sqli s WHERE s.username = '" + username + "'";
            Query query = entityManager.createQuery(jpql);
            List<Sqli> results = query.getResultList();
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
            String jpql = "SELECT s FROM Sqli s WHERE s.username = :username";
            Query query = entityManager.createQuery(jpql)
                    .setParameter("username", username);
            List<Sqli> results = query.getResultList();
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