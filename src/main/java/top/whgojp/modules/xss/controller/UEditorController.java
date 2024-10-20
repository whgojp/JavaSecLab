package top.whgojp.modules.xss.controller;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.text.UnicodeUtil;
import cn.hutool.json.JSONException;
import com.baomidou.mybatisplus.core.toolkit.ClassUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import top.whgojp.common.constant.SysConstant;
import top.whgojp.common.utils.UploadUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @description UEditor 相关接口配置
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/22 19:14
 */
@Slf4j
@Controller
@RequestMapping("/ueditor")
public class UEditorController {
    @RequestMapping("")
    public String ueditor() {
        return "vul/xss/ueditor";
    }

    /**
     * 获取config,json配置文件
     */
    @RequestMapping("/config")
    @ResponseBody
    public void getConfigInfo(HttpServletRequest request, HttpServletResponse response) {
        response.setContentType("application/json");

        String rootPath = "";
        // 判断当前系统是否是Windows系统
        if (isWindowsSystem()) {
            rootPath = ClassUtils.getDefaultClassLoader().getResource("").getPath() + "static/ueditor/jsp";
        } else {
            // 将config.json文件放在jar包同级目录下
            rootPath = "/Users/whgojp/Desktop/Security/JAVA/JavaSecLab/src/main/resources/static/lib/ueditor/jsp";
        }
        log.info("rootPath：{}", rootPath);
        try {
            response.setCharacterEncoding("UTF-8");
            String exec = new ActionEnterRewrite(request, rootPath, "/config.json").exec();
            log.info("exec：{}", UnicodeUtil.toString(exec));
            PrintWriter writer = response.getWriter();
            writer.write(exec);
            writer.flush();
            writer.close();
        } catch (IOException | JSONException e) {
            e.printStackTrace();
        }
    }

    @Autowired
    private SysConstant sysConstant;

    /**
     * UEditor 上传图片（单个或多个）---Windows使用（主要将config.json中的imageUrlPrefix改为本地地址）
     *
     * @return 返回提示信息
     */
    @PostMapping(value = "/upload")
    @ResponseBody
    public Object upLoadImgToWindows(MultipartFile upfile) {
        Map<String, Object> result = new HashMap<>();
        result.put("state", "上传失败");

        if (Objects.isNull(upfile) || upfile.isEmpty()) {
            result.put("message", "文件为空");
            return result;
        }

        String suffix = FilenameUtils.getExtension(upfile.getOriginalFilename());
        String uploadFolderPath = sysConstant.getUploadFolder();

        if (Objects.isNull(uploadFolderPath)) {
            log.error("上传文件失败，上传目录未配置");
            result.put("message", "上传目录未配置");
            return result;
        }

        String fileName = System.currentTimeMillis() + "." + suffix;
        String newFilePath = uploadFolderPath + "/" + fileName;

        try {
            File dest = new File(newFilePath);
            if (!dest.getParentFile().exists()) {
                boolean dirsCreated = dest.getParentFile().mkdirs();  // 创建父目录
                if (!dirsCreated) {
                    log.error("无法创建目录：{}", dest.getParentFile().getAbsolutePath());
                    result.put("message", "无法创建目录");
                    return result;
                }
            }
            upfile.transferTo(dest);  // 保存文件

            log.info("上传文件成功，文件路径：" + newFilePath);
            result.put("state", "SUCCESS");
            result.put("url", "http://127.0.0.1:8080/file/" + fileName);
            result.put("title", fileName);
            result.put("original", upfile.getOriginalFilename());
            result.put("type", fileName.substring(fileName.lastIndexOf(".")));
            result.put("size", upfile.getSize());
        } catch (IOException e) {
            log.error("文件上传失败", e);
            result.put("message", "文件上传失败：" + e.getMessage());
        }

        return result;
    }

    /**
     * 判断当前系统是否是Windows系统
     *
     * @return true：Windows系统，false：Linux系统
     */
    private boolean isWindowsSystem() {
        String property = System.getProperty("os.name").toLowerCase();
        return property.contains("windows");
    }

}
