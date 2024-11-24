package top.whgojp.modules.loginconfront.controller;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/11/24 00:16
 */
public class LoginRequest {
    private String encryptedUsername;
    private String encryptedPassword;

    // Getter和Setter方法
    public String getEncryptedUsername() {
        return encryptedUsername;
    }

    public void setEncryptedUsername(String encryptedUsername) {
        this.encryptedUsername = encryptedUsername;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }
}
