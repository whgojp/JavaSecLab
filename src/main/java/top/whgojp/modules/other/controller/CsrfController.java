package top.whgojp.modules.other.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @description 其他漏洞-跨站请求伪造
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/12 22:12
 */
@Slf4j
@Api(value = "CsrfController", tags = "其他漏洞-跨站请求伪造")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/other/csrf")
public class CsrfController {
    @ApiOperation("")
    @RequestMapping("")
    public String csrf() {
        return "vul/other/csrf";
    }
    @RequestMapping("/vul")
    @ResponseBody
    public R vulCsrf(String receiver, String amount, @AuthenticationPrincipal UserDetails userDetails){
        String currentUser = userDetails.getUsername();
        Map<String, Object> result = new HashMap<>();
        result.put("currentUser", currentUser);
        result.put("receiver", receiver);
        result.put("amount", amount);

        log.info("转账人："+currentUser+"收款人："+receiver+",转账金额："+amount);
        return R.ok(result);
    }

    @ApiOperation(value = "vul: referer绕过", notes = "通过referer限制，只允许本站发起的请求，但是referer可以伪造")
    @GetMapping("/transfer/referer")
    public Map<String, Object> transferMoneySafe(HttpServletRequest request, HttpServletResponse response, HttpSession session) {
        String from = (String) session.getAttribute("LoginUser");
        String amount = request.getParameter("amount");
        String receiver = request.getParameter("receiver");
        Map<String, Object> result = new HashMap<>();
        // 校验Referer 判断请求是否来自本站
        String referer = request.getHeader("referer");
        if (referer == null || !referer.startsWith("http://baidu.com")) {
            result.put("success", false);
            result.put("message", "referer is not valid");
            return result;
        }
        result.put("from", from);
        result.put("receiver", receiver);
        result.put("amount", amount);
        result.put("success", true);
        return result;
    }

    @GetMapping("/getCsrfToken")
    @ResponseBody
    public Map<String, Object> getCsrfToken(HttpSession session, Model model) {
        String token = UUID.randomUUID().toString();
        session.setAttribute("csrfToken", token);
        Map<String, Object> result = new HashMap<>();
        result.put("csrfToken", token);
        return result;
    }

    @GetMapping("/safe")
    @ResponseBody
    public Map<String, Object> safeCsrf(@RequestParam("receiver") String receiver,@RequestParam("amount") String amount,@AuthenticationPrincipal UserDetails userDetails,@RequestParam("csrfToken") String csrfToken,HttpSession session) {
        String currentUser = userDetails.getUsername();

        String sessionToken = (String) session.getAttribute("csrfToken");
        Map<String, Object> result = new HashMap<>();
        if (!csrfToken.equals(sessionToken)) {
            result.put("success", false);
            result.put("message", "Token失效！");
            return result;
        }
        result.put("currentUser", currentUser);
        result.put("receiver", receiver);
        result.put("amount", amount);
        result.put("csrfToken", csrfToken);
        return result;
    }

    @GetMapping("/safe2")
    @ResponseBody
    public Map<String, Object> safeCsrf(HttpServletRequest request, @RequestParam("receiver") String receiver, @RequestParam("amount") String amount, @AuthenticationPrincipal UserDetails userDetails, HttpSession session) {
        String currentUser = userDetails.getUsername();
        Map<String, Object> result = new HashMap<>();
        String referer = request.getHeader("referer");
        if (referer == null || !referer.startsWith("http://127.0.0.1")) {
            result.put("success", false);
            result.put("message", "referer无效！");
            return result;
        }
        result.put("currentUser", currentUser);
        result.put("receiver", receiver);
        result.put("amount", amount);
        return result;
    }

}
