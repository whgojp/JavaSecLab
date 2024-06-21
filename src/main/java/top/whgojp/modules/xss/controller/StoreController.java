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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.whgojp.common.base.AbstractController;
import top.whgojp.common.utils.MPPageConvert;
import top.whgojp.common.utils.R;
import top.whgojp.modules.xss.entity.Xss;
import top.whgojp.modules.xss.service.XssService;

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
@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/xss/store")
public class StoreController extends AbstractController{
    @Autowired
    private XssService xssService;

    @ApiOperation(value = "漏洞环境：原生无过滤", notes = "原生漏洞环境,未加任何过滤，将用户输入存储到数据库中")
    @RequestMapping("/a-vul1-store-raw")
    @ApiImplicitParam(name = "content", value = "请求参数", dataType = "String", paramType = "query", dataTypeClass = String.class)
    public R vul1StoreRaw(@ApiParam(name = "content", value = "请求参数", required = true) @RequestParam String content) {
        log.info("存储型XSS：" + content);

        final int code = xssService.insertOne(content);
        if (code == 1) {
            log.info("插入数据成功！");
            return R.ok();
        } else return R.error("数据插入失败");
    }

    @RequestMapping("/getXssList")
    public R getXssList(@RequestParam Map<String, Object> params) {
        QueryWrapper<Xss> queryWrapper = new QueryWrapper<>();
        queryWrapper.lambda().orderByDesc(Xss::getDate);

        IPage<Xss> listPage = xssService.page(mpPageConvert.<Xss>pageParamConvert(params), queryWrapper); // 使用实例对象调用方法
        return R.ok().setData(listPage);
    }

}
