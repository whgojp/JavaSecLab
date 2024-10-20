package top.whgojp.modules.components.shiro.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

/**
 * @description 组件漏洞-Shiro
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/12 22:53
 */
@Slf4j
@Api(value = "ShiroController", tags = "组件漏洞-Shiro")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/shiro")
public class ShiroController {
    @RequestMapping("")
    public String shiro() {
        return "vul/components/shiro";
    }

    @GetMapping("/getAESKey")
    @ResponseBody
    public R getShiroKey(){
        try{
            byte[] key = new CookieRememberMeManager().getCipherKey();
            return R.ok("Shiro AES密钥硬编码为："+new String(Base64.getEncoder().encode(key)));
        }catch (Exception ignored){
            return R.error("获取AES密钥失败！");
        }
    }

}
