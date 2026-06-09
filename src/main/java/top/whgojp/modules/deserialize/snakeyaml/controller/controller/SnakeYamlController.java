package top.whgojp.modules.deserialize.snakeyaml.controller.controller;

import groovy.sql.Sql;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import top.whgojp.common.utils.R;
import top.whgojp.modules.sqli.entity.Sqli;

/**
 * @description 反序列化 - SnakeYaml
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/19 19:53
 */
@Slf4j
@Api(value = "SnakeYamlController", tags = "反序列化 - SnakeYaml")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/snakeYaml")
public class SnakeYamlController {
    private final MessageSource messageSource;

    public SnakeYamlController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String snakeYaml(){
        return "vul/deserialize/snakeYaml";
    }

    @RequestMapping("/vul")
    @ResponseBody
    public R vul(String payload) {
        try {
            log.info("payload：" + payload);
            if (payload == null || payload.trim().isEmpty()) {
                return R.error(msg("common.payload.empty"));
            }
            Yaml y = new Yaml();
            Object result = y.load(payload);
            return R.ok(msg("deserialize.snakeYaml.result.vul", result));
        } catch (Exception e) {
            log.error("SnakeYaml反序列化失败", e);
            return R.error(msg("deserialize.snakeYaml.result.failed", e.getMessage()));
        }
    }

    @RequestMapping("/safe")
    @ResponseBody
    public R safe(@RequestParam(required = false, defaultValue = "name: JavaSecLab") String payload) {
        try {
            Yaml y = new Yaml(new SafeConstructor());
            Object result = y.load(payload);
            return R.ok(msg("deserialize.snakeYaml.result.safe", result));
        } catch (Exception e) {
            log.error("SnakeYaml安全解析失败", e);
            return R.error(msg("deserialize.snakeYaml.result.failed", e.getMessage()));
        }
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    /**
     * SnakeYaml有2个方法：
     * Yaml.load()：入参是一个字符串或者文件，返回一个Java对象
     * Yaml.dump(): 将一个对象转换为yaml文件形式
     * @param args
     */
    public static void main(String[] args) {
        Sqli sqli = new Sqli(1,"test","pass");
        sqli.setUsername("whgojp");
        Yaml yaml = new Yaml();
        System.out.println(yaml.dump(sqli));
        /**
         * !!top.whgojp.modules.sqli.entity.Sqli {id: 1, password: pass, username: whgojp}
         * !!用于强制类型转换，与fastjson中@type字段类型，!!top.whgojp.modules.sqli.entity.Sqli的意思是转换为Sqli类
         */
    }

}
