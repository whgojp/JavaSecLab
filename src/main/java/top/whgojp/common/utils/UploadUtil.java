package top.whgojp.common.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import top.whgojp.common.constant.SysConstant;

import java.io.File;
import java.io.IOException;

@Slf4j
@Component
public class UploadUtil {

    @Autowired
    private SysConstant sysConstant;

    public String uploadFile(MultipartFile file, String suffix, String path) throws IOException {
        // 从配置中获取上传目录
        String uploadFolderPath = sysConstant.getUploadFolder();
        try {
            // 确保目录存在
            File uploadDir = new File(uploadFolderPath);
            if (!uploadDir.exists() && !uploadDir.mkdirs()) {
                throw new IOException("Failed to create upload directory: " + uploadFolderPath);
            }
            // 构建文件路径
            String fileName = System.currentTimeMillis() + "." + suffix;
            String newFilePath = uploadFolderPath + File.separator + fileName;
            // 保存文件
            file.transferTo(new File(newFilePath));
            log.info("上传文件成功，文件路径：" + newFilePath);
            return "上传文件成功，文件路径：" + path + fileName;
        } catch (IOException e) {
            log.error("文件上传失败：{}", e.getMessage(), e);
            throw e; // 重新抛出异常供上层处理
        }
    }

}