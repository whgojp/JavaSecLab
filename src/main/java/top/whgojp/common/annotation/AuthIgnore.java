package top.whgojp.common.annotation;

import java.lang.annotation.*;

/**
 * api接口，忽略Token验证
 * @author whgojp
 * @email whgojp@foxmail.com
 * @date 2024-03-23 15:44
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthIgnore {

}
