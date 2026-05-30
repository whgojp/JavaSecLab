package top.whgojp.modules.csrf.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @description 跨站请求伪造
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/12 22:12
 */
@Slf4j
@Api(value = "CsrfController", tags = "跨站请求伪造")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/csrf")
public class CsrfController {
    private final MessageSource messageSource;

    public CsrfController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @ApiOperation("")
    @RequestMapping("")
    public String csrf() {
        return "vul/csrf/csrf";
    }
    @RequestMapping("/vul")
    @ResponseBody
    public R vul(String receiver, String amount, @AuthenticationPrincipal UserDetails userDetails){
        String currentUser = userDetails.getUsername();
        Map<String, Object> result = new HashMap<>();
        result.put("currentUser", currentUser);
        result.put("receiver", receiver);
        result.put("amount", amount);

        log.info("transfer from: {}, receiver: {}, amount: {}", currentUser, receiver, amount);
        return R.ok(result);
    }

    @ApiOperation(value = "vul: referer绕过", notes = "通过referer限制，只允许本站发起的请求，但是referer可以伪造")
    @GetMapping("/transfer/referer")
    public Map<String, Object> transferMoneySafe(HttpServletRequest request, HttpServletResponse response, HttpSession session) {
        String from = (String) session.getAttribute("LoginUser");
        String amount = request.getParameter("amount");
        String receiver = request.getParameter("receiver");
        Map<String, Object> result = new HashMap<>();
        // Validate Referer to determine whether the request comes from this site.
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

    @GetMapping("/safe1")
    @ResponseBody
    public Map<String, Object> safe1(@RequestParam("receiver") String receiver, @RequestParam("amount") String amount, @AuthenticationPrincipal UserDetails userDetails, @RequestParam(value = "csrfToken", required = false) String csrfToken, HttpSession session) {
        String currentUser = userDetails.getUsername();

        String sessionToken = (String) session.getAttribute("csrfToken");
        Map<String, Object> result = new HashMap<>();
        if (!constantTimeEquals(csrfToken, sessionToken)) {
            result.put("success", false);
            result.put("message", msg("csrf.result.tokenInvalid"));
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
    public Map<String, Object> safe2(HttpServletRequest request, @RequestParam("receiver") String receiver, @RequestParam("amount") String amount, @AuthenticationPrincipal UserDetails userDetails, HttpSession session) {
        String currentUser = userDetails.getUsername();
        Map<String, Object> result = new HashMap<>();
        String originOrReferer = request.getHeader("Origin");
        if (originOrReferer == null) {
            originOrReferer = request.getHeader("Referer");
        }
        if (!isTrustedSameOrigin(request, originOrReferer)) {
            result.put("success", false);
            result.put("message", msg("csrf.result.originRefererInvalid"));
            return result;
        }
        result.put("currentUser", currentUser);
        result.put("receiver", receiver);
        result.put("amount", amount);
        return result;
    }

    private boolean constantTimeEquals(String requestToken, String sessionToken) {
        if (requestToken == null || sessionToken == null) {
            return false;
        }
        return MessageDigest.isEqual(
                requestToken.getBytes(StandardCharsets.UTF_8),
                sessionToken.getBytes(StandardCharsets.UTF_8)
        );
    }

    private boolean isTrustedSameOrigin(HttpServletRequest request, String originOrReferer) {
        if (originOrReferer == null) {
            return false;
        }
        try {
            URI uri = new URI(originOrReferer);
            String expectedScheme = request.getScheme();
            String expectedHost = request.getServerName();
            int expectedPort = request.getServerPort();
            int actualPort = uri.getPort() == -1 ? defaultPort(uri.getScheme()) : uri.getPort();

            return expectedScheme.equalsIgnoreCase(uri.getScheme())
                    && expectedHost.equalsIgnoreCase(uri.getHost())
                    && expectedPort == actualPort;
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private int defaultPort(String scheme) {
        if ("https".equalsIgnoreCase(scheme)) {
            return 443;
        }
        return 80;
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
