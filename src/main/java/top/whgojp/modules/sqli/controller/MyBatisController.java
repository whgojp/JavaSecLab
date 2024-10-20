package top.whgojp.modules.sqli.controller;

import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.springframework.stereotype.Controller;
import top.whgojp.common.utils.R;
import io.swagger.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import top.whgojp.modules.sqli.entity.Sqli;
import top.whgojp.modules.sqli.service.SqliService;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * @description ORM框架-MyBatis下的sql注入问题
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/28 10:11
 */

/**
 * 这里会替换请求方式GET——》POST
 * 以及获取参数的方式
 */
@Api(value = "MyBatisController", tags = "SQL注入2-MyBatis")
@Controller
@RequestMapping("/sqli/mybatis")
public class MyBatisController {
    @Autowired
    private SqliService sqliService;
    Logger log = LoggerFactory.getLogger(JdbcController.class);

    @GetMapping("")
    public String sqliMyBatis() {
        return "vul/sqli/mybatis";
    }

    @ApiOperation(value = "安全代码：MyBatis-正常业务场景代码-原生方法", notes = "简单业务场景代码-增删改查使用MyBatis自带方法")
    @PostMapping("/safe1-nativeMethod")
    @ResponseBody
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", required = false, dataType = "Integer", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", required = false, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", required = false, dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safe1NativeMethod(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) Integer id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        try {
            int rowsAffected;
            String message;
            switch (type) {
                case "add":
                    rowsAffected = sqliService.nativeInsert(new Sqli(id, username, password));
                    message = (rowsAffected > 0) ? "数据插入成功 username:" + username + " password:" + password : "数据插入失败";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    rowsAffected = sqliService.nativeDelete(Integer.valueOf(id));
                    message = (rowsAffected > 0) ? "数据删除成功" : "数据删除失败 用户ID:" + id + " 不存在!";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    rowsAffected = sqliService.nativeUpdate(new Sqli(id, username, password));
                    message = (rowsAffected > 0) ? "数据更新成功" : "数据更新失败 用户ID不存在!";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    if (id != null) {
                        Sqli user;
                        if (sqliService.nativeSelect(id) != null) {
                            user = sqliService.nativeSelect(id);
                        } else return R.ok("用户ID不存在!");
                        message = "查询成功，用户名：" + user.getUsername() + " 密码：" + user.getPassword();
                        return R.ok(message);
                    } else {
                        return R.error("id为空!");
                    }

                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    // 简单的业务可以还可以使用自带的方法 当业务复杂时 需要自定义sql语句 就有可能存在sql注入
    @ApiOperation(value = "安全代码：MyBatis-正常业务场景代码-自定义方法", notes = "复杂业务场景代码-增删改查使用自定义方法")
    @PostMapping("/safe2-customMethod")
    @ResponseBody
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", required = false, dataType = "Integer", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", required = false, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", required = false, dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safe2CustomMethod(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) Integer id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        try {
            int rowsAffected;
            String message;
            switch (type) {
                case "add":
                    //这里插入数据使用MyBatiX插件生成的方法
                    rowsAffected = sqliService.customInsert(new Sqli(id, username, password));
                    message = (rowsAffected > 0) ? "数据插入成功 username:" + username + " password:" + password : "数据插入失败";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    //这里删除数据使用自定义代码
                    rowsAffected = sqliService.customDelete(Integer.valueOf(id));
                    message = (rowsAffected > 0) ? "数据删除成功" : "数据删除失败 用户ID:" + id + " 不存在!";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    //使用MyBatis注解
                    rowsAffected = sqliService.customUpdate(new Sqli(Integer.valueOf(id), username, password));
                    message = (rowsAffected > 0) ? "数据更新成功" : "数据更新失败 用户ID不存在!";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    final Sqli user = sqliService.customSelect(Integer.valueOf(id));
                    message = "查询成功，用户名：" + user.getUsername() + " 密码：" + user.getPassword();
                    return R.ok(message);
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }
        } catch (Exception e) {
            return R.error(e.toString());
        }
    }


    @ApiOperation(value = "特殊场景：order by问题")
    @PostMapping("/special1-OrderBy")
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
            List<Sqli> sqlis = new ArrayList<>();
            switch (type) {
                case "raw":
                    sqlis = sqliService.orderByVul(field);
                    break;
                case "prepareStatement":
                    sqlis = sqliService.orderByPrepareStatement(field);
                    break;
                case "writeList":
                    sqlis = sqliService.orderByWriteList(field);
                    break;
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }
            JSONArray jsonArray = convertToJsonArray(sqlis);
            return R.ok(jsonArray.toString());
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    private JSONArray convertToJsonArray(List<Sqli> sqlis) {
        JSONArray jsonArray = new JSONArray();

        for (Sqli sqli : sqlis) {
            JSONObject jsonObject = JSONUtil.createObj()
                    .put("id", sqli.getId().toString())
                    .put("username", sqli.getUsername())
                    .put("password", sqli.getPassword());
            jsonArray.put(jsonObject);
        }

        return jsonArray;
    }

    @ApiOperation(value = "特殊场景：使用%和模糊查询-like")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "keyword", value = "关键词", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    @PostMapping("/special2-Like")
    public R special2Like(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "keyword", value = "关键词") @RequestParam(required = false) String keyword
    ) {
        log.info("正在查找关键词：" + keyword);
        try {
            List<Sqli> sqlis = new ArrayList<>();
            switch (type) {
                case "raw":
                    sqlis = sqliService.likeVul(keyword);
                    break;
                case "prepareStatement":
                    sqlis = sqliService.likePrepareStatement(keyword);
                    break;
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }
            JSONArray jsonArray = convertToJsonArray(sqlis);
            return R.ok(jsonArray.toString());
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "特殊场景：in参数")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "keyword", value = "关键词", dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    @ResponseBody
    @PostMapping("/special3-In")
    public R special3In(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "scope", value = "关键词") @RequestParam(required = false) String scope) {
        try {
            List<Sqli> sqlis = new ArrayList<>();
            switch (type) {
                case "raw":
                    sqlis = sqliService.inVul(scope);
                    break;
                case "prepareStatement":
                    sqlis = sqliService.inPrepareStatement(scope);
                    break;
                case "Foreach":

                    sqlis = sqliService.inSafeForeach(parseInputToList(scope));
                    break;
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }
            JSONArray jsonArray = convertToJsonArray(sqlis);
            return R.ok(jsonArray.toString());
        } catch (Exception e) {
            log.error(e.toString());
            return R.error(e.toString());
        }
    }

    public static List<Integer> parseInputToList(String input) {
        List<Integer> resultList = new ArrayList<>();

        // 切割字符串并转换为整数
        String[] parts = input.split(",");
        for (String part : parts) {
            try {
                int number = Integer.parseInt(part.trim());
                resultList.add(number);
            } catch (NumberFormatException e) {
                // 如果无法解析为整数，可以选择处理异常或者跳过该部分
                System.err.println("Ignoring invalid number: " + part);
            }
        }

        return resultList;
    }


}
