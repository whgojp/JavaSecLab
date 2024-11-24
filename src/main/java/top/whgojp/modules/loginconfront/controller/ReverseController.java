package top.whgojp.modules.loginconfront.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

/**
 * @description 登录对抗-JS逆向
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/11/19 22:25
 */
@Slf4j
@Api(value = "ReverseController", tags = "登录对抗-JS逆向")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/loginconfront/reverse")
public class ReverseController {
    @RequestMapping("")
    public String reverse() {
        return "vul/loginconfront/reverse";
    }

    final String  REAL_USERNAME = "admin";
    final String REAL_PASSWORD = "admin123";

    // 固定密钥
    private static final String KEY = "FF38DC304A1D74B19F24A36C09FD6B72";

    // 生成签名的方法
    private String generateSign(Map<String, String> params) {
        TreeMap<String, String> sortedParams = new TreeMap<>(params);
        StringBuilder query = new StringBuilder();
        for (Map.Entry<String, String> entry : sortedParams.entrySet()) {
            query.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
        }
        if (query.length() > 0) {
            query.setLength(query.length() - 1);
        }
        return DigestUtils.md5DigestAsHex((query.toString() + KEY).getBytes());
    }

    // 请求签名绕过
    @PostMapping("/vul1")
    @ResponseBody
    public R vul1(@RequestBody Map<String, String> params) {
        log.info(params.toString());
        // 获取请求的参数
        String username = params.get("username");
        String password = params.get("password");
        String timestamp = params.get("timestamp");
        String sign = params.get("sign");

        // 校验参数是否齐全
        if (username == null || password == null || timestamp == null || sign == null) {
            return R.error("缺少必要参数");
        }

        Map<String, String> sortedParams = new HashMap<>();
        sortedParams.put("username", username);
        sortedParams.put("password", password);
        sortedParams.put("timestamp", timestamp);

        String generatedSign = generateSign(sortedParams);

        if (!generatedSign.equals(sign)) {
            return R.error("签名验证失败");
        }

        if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {
            return R.ok("登录成功！用户名：" + username + ",密码：" + password);
        } else {
            return R.error("用户名或密码错误");
        }
    }

//    @Value("${rsa.private.key}")
    private String privateKey = "-----BEGIN PRIVATE KEY-----\n" +
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDHoirq0G+M0epz\n" +
        "NCYkkCii2wF8oz/3IkK5NXztmUjRjUQUbrkmjz1osdbsGoFQl6lwoL2RwDk8lpZI\n" +
        "XkFgSW1jY0+ch8aQdqYp4XLBaHhpjLroyUGqv3UXDRbLHw9CWnQIkp+I8RCbPBSh\n" +
        "umKYC8oF0jWTTS94I1t/6Hzcm1+tkUkPBzQTQMxmr4GDd1GZB1ddH3buPfBc/2wT\n" +
        "mzSG/0ao0Py4Zj9Mo9G7buutUlUQVPO08FAzxCeRrb3Ijbv4Lo706mp4UuXGDz2u\n" +
        "KmCiSifKfJr8a7E7uRGRKeXuG+ON2RAQ4tUYmY7sqDM4WfOUIxR6aRtqQan84yaG\n" +
        "r0bI2pKhAgMBAAECggEAAh1AJfFUA8ezsLQoROyyQs/zIv+J8s4DVbmmC3sl3QhJ\n" +
        "ZLZWfNIkCkWQkJAS912f1FrzdFrMOw105Sp7DUVseegS71tgbuZpdJntZfR7X/zM\n" +
        "UaD+B8xUIGIfBW2HCG1zpfqYOMeleiC9BDMjOQKDns5UNcLpwjSM/cdieSX7xwIK\n" +
        "g/ZIP9ndW8pGZ4NpKknIf9+klKUX+bJr5y/qAWio89rnlxFMkemqXr8J7p+Fe7l/\n" +
        "bFXge4+EInGSbnTc0JsqN3bwh0qk8PW4J2NBQGA2KF7cTilkg96tgXUamz/fqbqd\n" +
        "Dyzy/+Qckmg1GsvVyJ/p5eDMuaBSUmpcgUvYzyF/EQKBgQDyYE0PRj3+KvEB+I6C\n" +
        "PCxkN6FZ6XKHU+XHP3Q8bYXSSNH3un/ikxc8/agR5osB9xpUbTAHLBHiSZiytt+g\n" +
        "priFzFiVzGsLNLOdOCivLIDRi15yg62980EyaSjautXdro8vfmXQcU5369MKoH9d\n" +
        "IiSIc0VcSHMJRxa6q4ErRIigCQKBgQDS2tDPdZYjWH6WfP4i7AMD/lAuEDHe1OMU\n" +
        "0kCnovT430u52kGY64Ae7p59coSG3AKJNj5ubZYq3Qt4DGCVKs17yWJYoMbpQH5o\n" +
        "orr61xRZ37TiSw6JTQHsE7Vo4EswKGZTHF3pBO+Coj9JHElkZCbdP2fhha6O+vLH\n" +
        "RLCatehT2QKBgA7FY6zcoQaOY2W1WioBtMrewQyTt5EbwdMkwNa17gPkwDcSvJx4\n" +
        "TmA/LTD6Fdqmzon6pYSqYOSji5TIpFRMFM7Cp1tpu9RQ/+lC9OfIFImwrq7X64y5\n" +
        "+G00D3NVE5eQ/dTtJRNQ9HFGg/QP1/M7E3LlY4K+P5R/Kplxvkt+v7zRAoGBALl7\n" +
        "maJWCwvuxfS14Y1w1jpGFdxfjK870MK5Lf0JobvoGiJUt83ApMURHcS235QOqABy\n" +
        "Ajt8FVSBfJxPLwspSvdwsR3L2Q7JGCoNtLQCTbm9y84hPplTb7Rvpe6rGBk2AMVt\n" +
        "t8LK/7KH7WnwAzPX0kRgiY5e3a6TXMwkRcLi8IwJAoGBAMiQrXp3Rdu91Jpiv2qQ\n" +
        "P3wAOUpBGwMMg5/AyGM3fPyQOKYY2pMoYmkXhFZD7lHDFgQmi9tSBTLj2/0kET/E\n" +
        "nHGICvwlri2P3vAClCmNzvPQ+AZp+GEy7dKYO5K5frVrnQ5O54MYyCeGG3Rdc5FS\n" +
        "iPqxlbGrQoUEtF5AG7YRadal\n" +
        "-----END PRIVATE KEY-----\n";

    private static String cleanKey(String key) {
        return key.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
    }

    // 解密函数
    private String decryptData(String encryptedData) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        String cleanedPrivateKey = cleanKey(privateKey);
        byte[] privateKeyBytes = Base64.getDecoder().decode(cleanedPrivateKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decryptedBytes = cipher.doFinal(decoded);
        return new String(decryptedBytes);
    }


    @PostMapping("/vul2")
    @ResponseBody
    public R vul2(@RequestBody LoginRequest request) {
//        log.info("用户名："+request.getEncryptedUsername()+",密码："+request.getEncryptedPassword());
        try {
            String decryptedUsername = decryptData(request.getEncryptedUsername());
            String decryptedPassword = decryptData(request.getEncryptedPassword());

//            log.info("解密后的用户名："+decryptedUsername+",密码："+decryptedPassword);

            if (REAL_USERNAME.equals(decryptedUsername) && REAL_PASSWORD.equals(decryptedPassword)) {
                return R.ok("登录成功！用户名：" + decryptedUsername + ",密码：" + decryptedPassword);
            } else {
                return R.error("用户名或密码错误！");
            }
        } catch (Exception e) {
            return R.error("解密失败！");
        }
    }


}
