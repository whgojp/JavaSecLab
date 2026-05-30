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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
                return R.error("No records found.");
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Query succeeded. Found ").append(results.size()).append(" records\n");
            for (Sqli sqli : results) {
                sb.append("ID: ").append(sqli.getId())
                        .append(", Username: ").append(sqli.getUsername())
                        .append(", Password: ").append(sqli.getPassword())
                        .append("\n");
            }
            String message = sb.toString();
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
    @AuthIgnore
    @ApiOperation(value = "JPA动态排序注入场景")
    @Transactional(rollbackFor = Exception.class)
    public R vul2(@RequestParam String orderBy) {
        try {
            String jpql = "SELECT s FROM Sqli s ORDER BY s." + orderBy;
            Query query = entityManager.createQuery(jpql);
            List<Sqli> results = query.getResultList();
            return R.ok(formatResults(results));
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
                return R.error("No records found.");
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Query succeeded. Found ").append(results.size()).append(" records\n");
            for (Sqli sqli : results) {
                sb.append("ID: ").append(sqli.getId())
                        .append(", Username: ").append(sqli.getUsername())
                        .append(", Password: ").append(sqli.getPassword())
                        .append("\n");
            }
            String message = sb.toString();
            log.info(message);
            return R.ok(message);
        } catch (Exception e) {
            String errorMsg = e.getMessage();
            log.error("查询失败: {}", errorMsg, e);
            return R.error(errorMsg);
        }
    }

    @RequestMapping("/safe-order")
    @ResponseBody
    @ApiOperation(value = "JPA动态排序安全场景")
    @Transactional(rollbackFor = Exception.class)
    public R safeOrder(@RequestParam String orderBy) {
        try {
            Map<String, String> orderByMap = new HashMap<>();
            orderByMap.put("id", "id");
            orderByMap.put("username", "username");
            orderByMap.put("password", "password");

            String safeOrderBy = orderByMap.get(orderBy);
            if (safeOrderBy == null) {
                return R.error("Invalid sort field.");
            }

            CriteriaBuilder cb = entityManager.getCriteriaBuilder();
            CriteriaQuery<Sqli> cq = cb.createQuery(Sqli.class);
            Root<Sqli> root = cq.from(Sqli.class);
            cq.select(root).orderBy(cb.asc(root.get(safeOrderBy)));

            List<Sqli> results = entityManager.createQuery(cq).getResultList();
            return R.ok(formatResults(results));
        } catch (Exception e) {
            String errorMsg = e.getMessage();
            log.error("查询失败: {}", errorMsg, e);
            return R.error(errorMsg);
        }
    }

    private String formatResults(List<Sqli> results) {
        if (results == null || results.isEmpty()) {
            return "No records found.";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Query succeeded. Found ").append(results.size()).append(" records\n");
        for (Sqli sqli : results) {
            sb.append("ID: ").append(sqli.getId())
                    .append(", Username: ").append(sqli.getUsername())
                    .append(", Password: ").append(sqli.getPassword())
                    .append("\n");
        }
        return sb.toString();
    }
}
