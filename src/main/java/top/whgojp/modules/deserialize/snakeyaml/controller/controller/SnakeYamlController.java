package top.whgojp.modules.deserialize.snakeyaml.controller.controller;

import groovy.sql.Sql;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
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
    @RequestMapping("")
    public String snakeYaml(){
        return "vul/deserialize/snakeYaml";
    }

    @RequestMapping("/vul")
    @ResponseBody
    public R vul(String payload) {
        log.info("payload："+payload);
        Yaml y = new Yaml();
        y.load(payload);
        return R.ok("[+]Java反序列化：SnakeYaml原生漏洞");
    }

    @PostMapping("/safe")
    @ResponseBody
    public R safe(String payload) {
        try {
            Yaml y = new Yaml(new SafeConstructor());
            y.load(payload);
            return R.ok("[+]Java反序列化：SnakeYaml安全构造");
        } catch (Exception e) {
            return R.error("[-]Java反序列化：SnakeYaml反序列化失败");
        }
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
