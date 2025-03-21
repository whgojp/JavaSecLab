package top.whgojp.common.utils;

import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * @description 用户输入数据校验
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/ueditor 14:19
 */
@Component
public class CheckUserInput {
    private static final Pattern SCRIPT_PATTERN = Pattern.compile("<script[^>]*>.*?</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern EVENT_PATTERN = Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE);
    private static final Pattern JAVASCRIPT_PATTERN = Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE);

    public String filter(String input) {
        if (input == null) {
            return "";
        }
        
        // 基本HTML转义
        String filtered = HtmlUtils.htmlEscape(input);
        
        // 移除script标签
        filtered = SCRIPT_PATTERN.matcher(filtered).replaceAll("");
        
        // 移除事件处理器
        filtered = EVENT_PATTERN.matcher(filtered).replaceAll("");
        
        // 移除javascript:协议
        filtered = JAVASCRIPT_PATTERN.matcher(filtered).replaceAll("");
        
        return filtered;
    }

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
            message = "请输入用户id";
        }
        return message;
    }

    /**
     * 后端白名单过滤
     */
    public String checkXssWhiteList(String content) {

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
    public boolean checkSqlWhiteList(String content) {
        String[] white_list = {"id", "username", "password"};
        for (String s : white_list) {
            if (content.toLowerCase().equals(s)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 文件上传白名单
     */
    public boolean checkFileSuffixWhiteList(String suffix) {
        String[] white_list = {"jpg", "png", "gif","jpeg","bmp","ico"};
        for (String s : white_list) {
            if (suffix.toLowerCase().contains(s)) {
                return true;
            }
        }
        return false;
    }


    // 定义 URL 白名单
    private static final List<String> WhiteUrlList = new ArrayList<>();

    static {
//        WhiteUrlList.add("baidu.com");
//        WhiteUrlList.add("bilibili.com");
        WhiteUrlList.add("csdn.net");
    }
    /**
     * URL跳转过滤
     */
    public boolean checkURL(String url) {
        for (String blackUrl : WhiteUrlList) {
            if (url.toLowerCase().contains(blackUrl.toLowerCase())) {
                return false;
            }
        }
        return true;
    }

    /**
     * ssrf：判断http(s)协议
     */
    public boolean isHttp(String url){
        return url.startsWith("http://") || url.startsWith("https://");
    }
    /**
     * ssrf：请求域名白名单
     */
    public boolean ssrfWhiteList(String url) {
        List<String> urlList = new ArrayList<>(Arrays.asList("baidu.com", "www.baidu.com", "whgojp.top"));
        try {
            URI uri = new URI(url.toLowerCase());
            String host = uri.getHost();
            return urlList.contains(host);
        } catch (URISyntaxException e) {
            System.out.println(e);
            return false;
        }
    }

}
