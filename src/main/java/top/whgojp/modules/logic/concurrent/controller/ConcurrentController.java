package top.whgojp.modules.logic.concurrent.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;

import java.math.BigDecimal;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @description 逻辑漏洞-并发安全
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2026/5/26
 */
@Slf4j
@Api(value = "ConcurrentController", tags = "逻辑漏洞-并发安全")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/logic/concurrent")
public class ConcurrentController {
    private final MessageSource messageSource;
    private final AtomicReference<BigDecimal> userMoney = new AtomicReference<>(new BigDecimal("1000.00"));
    private final Set<String> paidOrders = ConcurrentHashMap.newKeySet();
    private final Object paymentLock = new Object();

    public ConcurrentController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String concurrent() {
        return "vul/logic/concurrent/concurrent";
    }

    @ApiOperation("漏洞场景：竞态条件重复支付")
    @RequestMapping("/vul")
    @ResponseBody
    public R vul(@RequestParam String orderId, @RequestParam double amount) {
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        BigDecimal currentMoney = userMoney.get();
        BigDecimal payAmount = BigDecimal.valueOf(amount);
        if (currentMoney.compareTo(payAmount) < 0) {
            return R.error(msg("logic.concurrent.result.insufficientBalance"));
        }
        userMoney.set(currentMoney.subtract(payAmount));
        return R.ok(msg("logic.concurrent.result.paymentSuccess", orderId, userMoney.get()));
    }

    @ApiOperation("安全场景：同步锁和幂等校验")
    @RequestMapping("/safe")
    @ResponseBody
    public R safe(@RequestParam String orderId, @RequestParam double amount) {
        BigDecimal payAmount = BigDecimal.valueOf(amount);
        synchronized (paymentLock) {
            if (paidOrders.contains(orderId)) {
                return R.error(msg("logic.concurrent.result.orderPaid", orderId));
            }
            BigDecimal currentMoney = userMoney.get();
            if (currentMoney.compareTo(payAmount) < 0) {
                return R.error(msg("logic.concurrent.result.insufficientBalance"));
            }
            paidOrders.add(orderId);
            userMoney.set(currentMoney.subtract(payAmount));
            return R.ok(msg("logic.concurrent.result.paymentSuccess", orderId, userMoney.get()));
        }
    }

    @ApiOperation("重置并发安全测试数据")
    @RequestMapping("/reset")
    @ResponseBody
    public R reset() {
        userMoney.set(new BigDecimal("1000.00"));
        paidOrders.clear();
        return R.ok(msg("logic.concurrent.result.reset"));
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }
}
