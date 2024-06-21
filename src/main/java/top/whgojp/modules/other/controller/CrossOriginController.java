package top.whgojp.modules.other.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import top.whgojp.common.utils.R;

/**
 * @description 跨源安全问题
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/6 20:46
 */
@Slf4j
@Api(value = "ReflectController", tags = "跨站脚本-Dom型XSS")
@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/other/CrossOrigin")
public class CrossOriginController {

    @ApiOperation("")
    @RequestMapping("/cros")
    public R Cros(){

        return R.ok();
    }

}
