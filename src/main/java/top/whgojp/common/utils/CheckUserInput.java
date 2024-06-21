package top.whgojp.common.utils;

import org.springframework.stereotype.Component;

/**
 * @description 用户输入数据校验
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/1 14:19
 */
@Component
public class CheckUserInput {
    public String checkUser(String username, String password, Integer id) {
        String message = "";
        if (username == null || username.isEmpty()) {
            message = "请输入用户名";
        } else if (password == null || password.isEmpty()) {
            message = "请输入密码";
        } else if (id == null) {
            message = "请输入用户id";
        }
        if (message.isEmpty()) {  // 这里使用 isEmpty() 方法来检查 message 是否为空
            return message;
        } else {
            return message;
        }
    }
    public String checkUser(String username, String password) {
        String message = "";
        if (username == null || username.isEmpty()) {
            message = "请输入用户名";
        } else if (password == null || password.isEmpty()) {
            message = "请输入密码";
        }
        if (message.isEmpty()) {
            return message;
        } else {
            return message;
        }
    }
    public String checkUser(Integer id) {
        String message = "";
        if (id == null) {
            message="请输入用户id";
        }
        return message;
    }

    /**
     *  后端白名单过滤
     */
    public String checkXssWhiteList(String content){

        return content;
    }

    /**
     * SQL关键词黑名单
     */
    public boolean checkSqlBlackList(String content) {
        String[] black_list = {"'", ";", "--", "+", ",", "%", "=", ">", "<", "*", "(", ")", "and", "or", "exec", "insert", "select", "delete", "update", "count", "drop", "chr", "mid", "master", "truncate", "char", "declare"};
        for (String s : black_list) {
            if (content.toLowerCase().contains(s)) {
                return true;
            }
        }
        return false;
    }
    /**
     * SQL注入关键词白名单
     */
    public boolean checkSqlWhiteList(String content){
        String[] white_list = {"id","user","pass"};
        for (String s : white_list) {
            if (content.toLowerCase().contains(s)) {
                return true;
            }
        }
        return false;
    }

}
