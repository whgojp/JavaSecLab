package top.whgojp.modules.spel.controller;

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
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

/**
 * @description JAVA专题-SPEL 表达式注入
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/9 14:08
 */
@Slf4j
@Api(value = "SPELController", tags = "JAVA专题-SPEL 表达式注入")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/spel")
public class SPELController {
    @RequestMapping("")
    public String spel() {
        return "vul/spel/spel";
    }

    @ApiOperation(value = "漏洞场景：原生漏洞场景", notes = "当参数未经过滤时，攻击者可以注入恶意的SPEL表达式，执行任意代码")
    @ResponseBody
    @ApiImplicitParam(name = "ex", value = "表达式", dataType = "String", paramType = "query", dataTypeClass = String.class)
    @GetMapping("/vul")
    public R vul(@ApiParam(name = "ex", value = "表达式", required = true) @RequestParam String ex) {
        // 创建SpEL解析器，ExpressionParser接口用于表示解析器，SpelExpressionParser为默认实现
        ExpressionParser parser = new SpelExpressionParser();
//        Expression expression = parser.parseExpression(ex);
//        String result =  expression.getValue().toString();
        // 构造上下文 上下文其实就是设置好某些变量的值，执行表达式时根据这些设置好的内容区获取值 在不配置的情况下具有默认类型的上下文
        EvaluationContext evaluationContext = new StandardEvaluationContext();
        // 解析表达式，将用户输入的字符串解析为Expression对象
        Expression exp = parser.parseExpression(ex);
        // 通过上下文计算表达式的值，并将结果转换为字符串
        String result = exp.getValue(evaluationContext).toString();
        log.info("[+]SPEL表达式注入："+ex);
        return R.ok(result);
    }

    @ResponseBody
    @ApiImplicitParam(name = "ex", value = "表达式", dataType = "String", paramType = "query", dataTypeClass = String.class)
    @GetMapping("/safe")
    public R safe(@ApiParam(name = "ex", value = "表达式", required = true) @RequestParam String ex) {
        // 使用 SimpleEvaluationContext 限制表达式功能(Java类型引用、构造函数调用、Bean引用)，防止危险的操作
        ExpressionParser parser = new SpelExpressionParser();
        EvaluationContext simpleContext = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        Expression exp = parser.parseExpression(ex);
        String result = exp.getValue(simpleContext).toString();
        log.info("[-]SPEL表达式注入："+ex);
        return R.ok(result);
    }


}
