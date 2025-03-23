package top.whgojp.modules.logic.pay.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;

import java.math.BigDecimal;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.HashMap;

/**
 * @description 逻辑漏洞-支付漏洞
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/28 22:07
 */
@Slf4j
@Api(value = "PayController", tags = "逻辑漏洞-支付漏洞")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/logic/pay")
public class PayController {
    // 用户余额
    private final AtomicReference<BigDecimal> userMoney = new AtomicReference<>(new BigDecimal("1000.00"));
    // 商品单价（用于服务端验证）
    private final BigDecimal goodPrice = new BigDecimal("100.00");
    // 订单状态缓存
    private final Map<String, OrderStatus> orderStatusMap = new ConcurrentHashMap<>();
    // 支付状态缓存（用于防止重复支付）
    private final Map<String, Boolean> paymentStatusMap = new ConcurrentHashMap<>();
    
    @RequestMapping("")
    public String pay() {
        return "vul/logic/pay/pay";
    }

    /**
     * 订单状态类
     */
    private static class OrderStatus {
        BigDecimal amount;
        boolean isPaid;
        String orderId;
        
        public OrderStatus(String orderId, BigDecimal amount) {
            this.orderId = orderId;
            this.amount = amount;
            this.isPaid = false;
        }
    }

    /**
     * 漏洞场景1：支付金额参数篡改
     * 由于未对客户端传入的价格参数进行验证，攻击者可以修改支付金额
     */
    @ApiOperation("支付金额参数篡改漏洞")
    @RequestMapping("/vul1")
    @ResponseBody
    public R vul1(@RequestParam String count, @RequestParam String price) {
        try {
            double totalPrice = Integer.parseInt(count) * Double.parseDouble(price);
            log.info("用户需支付金额：" + totalPrice);
            
            // 直接使用客户端传入的价格，未与服务端商品实际价格进行校验
            BigDecimal currentMoney = userMoney.get();
            if (currentMoney.compareTo(BigDecimal.valueOf(totalPrice)) < 0) {
                return R.error("支付金额不足，支付失败！");
            }
            userMoney.set(currentMoney.subtract(BigDecimal.valueOf(totalPrice)));
            return R.ok("支付成功！剩余余额：" + userMoney.get());
        } catch (Exception e) {
            return R.error(e.toString());
        }
    }

    /**
     * 漏洞场景2：订单重放攻击
     * 由于未对订单是否重复支付进行验证，攻击者可以重复发送相同的支付请求
     */
    @ApiOperation("订单重放攻击漏洞")
    @RequestMapping("/vul2")
    @ResponseBody
    public R vul2(@RequestParam String orderId, @RequestParam double amount) {
        // 未检查订单是否已支付
        // 这里应该使用paymentStatusMap检查订单是否已支付，但为了演示漏洞，故意不检查
        BigDecimal currentMoney = userMoney.get();
        if (currentMoney.compareTo(BigDecimal.valueOf(amount)) < 0) {
            return R.error("余额不足");
        }
        userMoney.set(currentMoney.subtract(BigDecimal.valueOf(amount)));
        return R.ok("支付成功！剩余余额：" + userMoney.get());
    }

    /**
     * 漏洞场景3：竞态条件漏洞
     * 由于未正确处理并发支付请求，可能导致重复扣款或余额计算错误
     */
    @ApiOperation("竞态条件漏洞")
    @RequestMapping("/vul3")
    @ResponseBody
    public R vul3(@RequestParam String orderId, @RequestParam double amount) {
        // 模拟处理延迟
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        BigDecimal currentMoney = userMoney.get();
        if (currentMoney.compareTo(BigDecimal.valueOf(amount)) < 0) {
            return R.error("余额不足");
        }
        userMoney.set(currentMoney.subtract(BigDecimal.valueOf(amount)));
        return R.ok("支付成功！剩余余额：" + userMoney.get());
    }

    /**
     * 漏洞场景4：支付流程绕过
     * 由于状态校验不完整，攻击者可能绕过支付流程直接修改订单状态
     */
    @ApiOperation("支付流程绕过漏洞 - 创建订单")
    @RequestMapping("/vul4/create")
    @ResponseBody
    public R createOrder(@RequestParam String orderId, @RequestParam double amount) {
        OrderStatus status = new OrderStatus(orderId, BigDecimal.valueOf(amount));
        orderStatusMap.put(orderId, status);
        Map<String, Object> data = new HashMap<>();
        data.put("orderId", orderId);
        data.put("amount", amount);
        return R.ok("订单创建成功").put("data", data);
    }

    @ApiOperation("支付流程绕过漏洞 - 查询订单状态")
    @RequestMapping("/vul4/status")
    @ResponseBody
    public R getOrderStatus(@RequestParam String orderId) {
        OrderStatus status = orderStatusMap.get(orderId);
        if (status == null) {
            return R.error("订单不存在");
        }
        Map<String, Object> data = new HashMap<>();
        data.put("orderId", status.orderId);
        data.put("amount", status.amount);
        data.put("isPaid", status.isPaid);
        return R.ok().put("data", data);
    }

    @ApiOperation("支付流程绕过漏洞 - 支付通知")
    @RequestMapping("/vul4/notify")
    @ResponseBody
    public R paymentNotify(@RequestParam String orderId, @RequestParam boolean success) {
        // 未验证通知来源，直接更新订单状态
        OrderStatus status = orderStatusMap.get(orderId);
        if (status == null) {
            return R.error("订单不存在");
        }
        status.isPaid = success;
        return R.ok("状态更新成功");
    }


    /**
     * 漏洞场景5：整数溢出漏洞
     * 当count或price数值过大时，可能会导致整数溢出
     */
    @ApiOperation("整数溢出漏洞")
    @RequestMapping("/vul5")
    @ResponseBody
    public R integerOverflow(@RequestParam String count, @RequestParam String price) {
        try {
            Integer countValue = Integer.valueOf(count);
            Integer priceValue = Integer.valueOf(price);

            // 整数溢出场景：当 count 或 price 数值过大时，可能会导致溢出
            int totalAmount = countValue * priceValue;
            log.info("用户需支付金额：" + totalAmount);

            BigDecimal currentMoney = userMoney.get();
            if (currentMoney.compareTo(BigDecimal.valueOf(totalAmount)) < 0) {
                return R.error("支付金额不足，支付失败！");
            }
            userMoney.set(currentMoney.subtract(BigDecimal.valueOf(totalAmount)));
            return R.ok("支付成功！剩余余额：" + userMoney.get());
        } catch (Exception e) {
            return R.error("无效的输入，请输入有效的数量和价格！");
        }
    }

    /**
     * 漏洞场景6：浮点数精度漏洞
     * 由于未正确处理浮点数精度，可能导致金额计算不准确
     */
    @ApiOperation("浮点数精度漏洞")
    @RequestMapping("/vul6")
    @ResponseBody
    public R floatingPointPrecision(@RequestParam String count, @RequestParam String price) {
        try {
            // 使用BigDecimal处理金额计算，避免浮点数精度问题
            BigDecimal amountValue = new BigDecimal(price).multiply(new BigDecimal(count));
            log.info("用户需支付金额：" + amountValue);

            BigDecimal currentMoney = userMoney.get();
            if (currentMoney.compareTo(amountValue) < 0) {
                return R.error("支付金额不足，支付失败！");
            }
            userMoney.set(currentMoney.subtract(amountValue));
            return R.ok("支付成功！剩余余额：" + userMoney.get());
        } catch (Exception e) {
            return R.error("无效的输入，请输入有效的数量和价格！");
        }
    }

    @ApiOperation("重置用户余额")
    @RequestMapping("/resetBalance")
    @ResponseBody
    public R resetBalance() {
        userMoney.set(new BigDecimal("1000.00"));
        return R.ok("余额已重置为1000.00元");
    }
}
