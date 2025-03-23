package top.whgojp.modules.mshell.controller;

import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.Context;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;

/**
 * 内存马基础控制器
 * 提供获取Context等通用方法
 * 
 * @author whgojp
 * @date 2024/03/20
 */
@Slf4j
public class BaseMemShellController {

    /**
     * 获取Tomcat的Context对象
     * 通过反射获取内部的context字段
     * 
     * @return Tomcat的Context对象
     * @throws Exception 如果获取失败
     */
    protected Context getContext() throws Exception {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            throw new RuntimeException("获取ServletRequestAttributes失败");
        }

        HttpServletRequest request = attributes.getRequest();
        // 获取包装的request对象
        Field requestField = request.getClass().getDeclaredField("request");
        requestField.setAccessible(true);
        Object requestObject = requestField.get(request);
        
        // 获取内部的context字段
        Field contextField = requestObject.getClass().getDeclaredField("context");
        contextField.setAccessible(true);
        Object contextObject = contextField.get(requestObject);
        
        return (Context) contextObject;
    }
}
