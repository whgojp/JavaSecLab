package top.whgojp.modules.ssti.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @description JAVA专题-SSTI 模版注入
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/9 14:14
 */
@Slf4j
@Api(value = "SSTIController", tags = "JAVA专题-SSTI 模版注入")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/ssti")
public class SSTIController {
    @RequestMapping("")
    public String ssti() {
        return "vul/ssti/ssti";
    }

    @ApiOperation(value = "漏洞环境：Thymeleaf模板注入", notes = "如果参数未经过滤，攻击者可以注入恶意模板参数，执行任意代码。")
    @ApiImplicitParam(name = "para", value = "用户输入参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    @GetMapping("/vul1-thymeleaf")
    public String sstiVul(@ApiParam(name = "para", value = "用户输入参数", required = true) @RequestParam String para, Model model) {
//        model.addAttribute("para", para);
//        return "vul/ssti/vul"; // 将参数 para 传递到模板 "vul/ssti/template"

        // 用户输入直接拼接到模板路径，可能导致SSTI（服务器端模板注入）漏洞
        return "/vul/ssti/" + para;
    }
    @GetMapping("/vul2-thymeleaf/{path}")
    public void sstiVul2(@PathVariable String path) {
        log.info("SSTI注入："+path);
    }
    @GetMapping("/vul3-thymeleaf")
    public String sstiVul3(@ApiParam(name = "para", value = "用户输入参数", required = true) @RequestParam String para, Model model) {
        model.addAttribute("templateContent", para);
        return "vul/ssti/vul"; // 将参数 para 传递到模板 "vul/ssti/vul"
    }

    @GetMapping("/safe-thymeleaf")
    public String sstiSafe(@ApiParam(name = "para", value = "用户输入参数", required = true) @RequestParam String para, Model model) {
        List<String> white_list = new ArrayList<>(Arrays.asList("vul", "ssti"));
        if (white_list.contains(para)){
            return "vul/ssti" + para;
        } else{
            return "common/401";
        }
    }
    @GetMapping("/safe2/{path}")
    public void sstiSafe2(@PathVariable String path, HttpServletResponse response) {
        log.info("SSTI注入："+path);
    }



}