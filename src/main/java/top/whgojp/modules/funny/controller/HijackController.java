package top.whgojp.modules.funny.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2025/1/17 16:31
 */
@Slf4j
@Api(value = "HijackController", tags = "劫持模块")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/funny/hijack")
public class HijackController {
    @RequestMapping()
    public String hijack(){
        return "vul/funny/hijack";
    }

}
