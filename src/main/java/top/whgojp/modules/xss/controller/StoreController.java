package top.whgojp.modules.xss.controller;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.apache.xpath.operations.Mod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.base.AbstractController;
import top.whgojp.common.utils.MPPageConvert;
import top.whgojp.common.utils.R;
import top.whgojp.modules.xss.entity.Xss;
import top.whgojp.modules.xss.service.XssService;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @description 跨站脚本-存储型XSS
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/23 17:24
 */
@Slf4j
@Api(value = "StoreController", tags = "跨站脚本-存储型XSS")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/xss/store")
public class StoreController extends AbstractController{
    @Autowired
    private XssService xssService;

    @RequestMapping("")
    public String xssStore() {
        return "vul/xss/store";
    }

    @ApiOperation(value = "漏洞场景：原生无过滤", notes = "原生漏洞场景,未加任何过滤，将用户输入存储到数据库中")
    @PostMapping("/vul")
    @ResponseBody
    @ApiImplicitParam(name = "payload", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public R vul(@ApiParam(name = "payload", value = "请求参数", required = true) @RequestParam String payload,HttpServletRequest request) {
        log.info("[+]XSS-存储性-原生无过滤：" + payload);
        String ua = request.getHeader("User-Agent");
        final int code = xssService.insertOne(payload,ua);
        if (code == 1) {
            log.info("插入数据成功！");
            return R.ok("插入数据成功！");
        } else return R.error("数据插入失败");
    }

    @RequestMapping("/getXssList")
    @ResponseBody
    public R getXssList(@RequestParam Map<String, Object> params) {
        QueryWrapper<Xss> queryWrapper = new QueryWrapper<>();
        queryWrapper.lambda().orderByDesc(Xss::getDate);
        IPage<Xss> listPage = xssService.page(mpPageConvert.<Xss>pageParamConvert(params), queryWrapper); // 使用实例对象调用方法
        return R.ok().setData(listPage);
    }
    @PostMapping("/deleteOne")
    @ResponseBody
    public R deleteOne(@RequestParam int id){
        if (xssService.deleteById(id)==1){
            return R.ok("删除成功！");
        }else return R.error("删除失败！");
    }
}
