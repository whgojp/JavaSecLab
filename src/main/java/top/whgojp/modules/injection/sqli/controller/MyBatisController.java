package top.whgojp.modules.injection.sqli.controller;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import top.whgojp.common.utils.R;
import io.swagger.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import top.whgojp.modules.injection.sqli.entity.Users;
import top.whgojp.modules.injection.sqli.service.UsersService;

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
@RestController
@RequestMapping("/sqli/mybatis")
public class MyBatisController {
    @Autowired
    private UsersService usersService;
    Logger log = LoggerFactory.getLogger(JdbcController.class);

    @ApiOperation(value = "安全代码：MyBatis-正常业务场景代码-原生方法", notes = "简单业务场景代码-增删改查使用MyBatis自带方法")
    @PostMapping("/safecode1-nativemethod")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", required = false, dataType = "Integer", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", required = false, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", required = false, dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safeCode1NativeMethod(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) Integer id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        try {
            int rowsAffected;
            String message;
            switch (type) {
                case "add":
                    if (username == null || password == null) return R.error("username或password为空");
                    rowsAffected = usersService.nativeInsert(new Users(id, username, password));
                    message = (rowsAffected > 0) ? "数据插入成功" : "数据插入失败";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    rowsAffected = usersService.nativeDelete(Integer.valueOf(id));
                    message = (rowsAffected > 0) ? "数据删除成功" : "数据删除失败";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    rowsAffected = usersService.nativeUpdate(new Users(id, username, password));
                    message = (rowsAffected > 0) ? "数据更新成功" : "数据更新失败 用户ID不存在!";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    log.info("id:" + id);
                    if (id != null) {
                        Users user;
                        if (usersService.nativeSelect(id) != null) {
                            user = usersService.nativeSelect(id);
                        } else return R.ok("用户ID不存在!");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("id", user.getId());
                        jsonObject.put("username", user.getUser());
                        jsonObject.put("password", user.getPass());
                        log.info("数据查询成功：" + jsonObject.toString());
                        return R.ok().setData(jsonObject);
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
    @PostMapping("/safecode2-custommethod")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", required = false, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", required = false, dataType = "String", paramType = "query", dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", required = false, dataType = "String", paramType = "query", dataTypeClass = String.class)
    })
    public R safeCode2CustomMethod(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        try {
            int rowsAffected;
            String message;
            switch (type) {
                case "add":
                    if (username == null || password == null) return R.error("username或password为空");
                    //这里插入数据使用MyBatiX插件生成的方法
                    rowsAffected = usersService.customInsert(new Users(Integer.valueOf(id), username, password));
                    message = (rowsAffected > 0) ? "数据插入成功" : "数据插入失败";
                    log.info(message);
                    return R.ok(message);
                case "delete":
                    //这里删除数据使用自定义代码
                    rowsAffected = usersService.customDelete(Integer.valueOf(id));
                    message = (rowsAffected > 0) ? "数据删除成功" : "数据删除失败";
                    log.info(message);
                    return R.ok(message);
                case "update":
                    //使用MyBatis注解
                    rowsAffected = usersService.customUpdate(new Users(Integer.valueOf(id), username, password));
                    message = (rowsAffected > 0) ? "数据更新成功" : "数据更新失败";
                    log.info(message);
                    return R.ok(message);
                case "select":
                    final Users user = usersService.customSelect(Integer.valueOf(id));
                    final JSONObject jsonObject = JSONUtil.createObj();
                    jsonObject.put("id", user.getId());
                    jsonObject.put("username", user.getUser());
                    jsonObject.put("password", user.getPass());
                    return R.ok().setData(jsonObject);
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }
        } catch (Exception e) {
            return R.error(e.toString());
        }
    }


    @ApiOperation(value = "特殊场景：order by问题")
    @PostMapping("/special1")
    public R special1() {
        return R.ok();
    }

    @ApiOperation(value = "特殊场景：like查询")
    @PostMapping("/special2")
    public R special2() {
        return R.ok();
    }

    @ApiOperation(value = "特殊场景：in参数")
    @PostMapping("/special3")
    public R special3() {
        return R.ok();
    }


}
