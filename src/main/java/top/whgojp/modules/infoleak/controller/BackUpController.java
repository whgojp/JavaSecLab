package top.whgojp.modules.infoleak.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/19 13:15
 */
@Slf4j
@Api(value = "BackUpController", tags = "敏感信息泄漏-备份文件")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/infoLeak/backUp")
public class BackUpController {
    @RequestMapping("")
    public String backUp() {
        return "vul/infoleak/backup";
    }
}
