package top.whgojp.common.utils;

import cn.hutool.core.date.DateUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import top.whgojp.common.constant.SysConstant;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

@Slf4j
@Component
public class UploadUtil {

    @Autowired
    private SysConstant sysConstant;


    private static final String UPLOAD_DIR = "uploads"; // 可以改成配置文件中的路径

    public String uploadFile(MultipartFile file, String suffix,String path) throws IOException {

        String uploadFolderPath = sysConstant.getUploadFolder();

        try {

            String fileName = +DateUtil.current() + "."+suffix;
            String newFilePath = uploadFolderPath + "/" + fileName;

            file.transferTo(new File(newFilePath)); // 将文件保存到指定路径
            log.info("上传文件成功，文件路径：" + newFilePath);
            return "上传文件成功，文件路径：" + path + fileName;
        } catch (IOException e) {
            e.printStackTrace(); // 打印异常堆栈信息
            log.info("文件上传失败" + e.getMessage());
            return "文件上传失败" + e.getMessage();
        }

    }
}