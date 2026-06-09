package top.whgojp.common.enums;


import java.util.HashMap;
import java.util.Map;

/**
 * @description 登录事件
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/17 12:16
 */
public enum LoginError {


    FAILURE(0, "login.error.failure"),

    BADCREDENTIALS(1, "login.error.badCredentials"),

    LOCKED(2, "login.error.locked"),

    ACCOUNTEXPIRED(3, "login.error.accountExpired"),

    USERNAMENOTFOUND(4, "login.error.usernameNotFound"),

    CAPTCHANOTFOUND(5,"login.error.captchaNotFound"),
    CAPTCHAEXPIRED(6,"login.error.captchaExpired"),
    CAPTCHAERROR(7,"login.error.captchaError");


    private Integer type;

    private String messageCode;

    private final static Map<Integer, LoginError> mappings = new HashMap<>();

    static {
        mappings.put(FAILURE.type, FAILURE);
        mappings.put(BADCREDENTIALS.type, BADCREDENTIALS);
        mappings.put(LOCKED.type, LOCKED);
        mappings.put(ACCOUNTEXPIRED.type, ACCOUNTEXPIRED);
        mappings.put(USERNAMENOTFOUND.type, USERNAMENOTFOUND);
        mappings.put(CAPTCHANOTFOUND.type, CAPTCHANOTFOUND);
        mappings.put(CAPTCHAEXPIRED.type, CAPTCHAEXPIRED);
        mappings.put(CAPTCHAERROR.type, CAPTCHAERROR);

    }

    public static LoginError resolve(Integer type) {
        return type != null ? mappings.get(type) : null;
    }

    public static String getMessageCode(Integer type) {
        LoginError loginError = resolve(type);

        return loginError != null ? loginError.messageCode : null;
    }

    LoginError(Integer type, String messageCode) {
        this.type = type;
        this.messageCode = messageCode;
    }

    public Integer getType() {
        return type;
    }

    public void setType(Integer type) {
        this.type = type;
    }

    public String getMessageCode() {
        return messageCode;
    }

    public void setMessageCode(String messageCode) {
        this.messageCode = messageCode;
    }
}
