package top.whgojp.modules.xss.controller;

/**
 * @description <功能描述>
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/23 10:06
 */
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.UUID;


@Slf4j
public class FileUtils {

    public static String upLoadFile(MultipartFile file, String path) {
        if (file == null || file.isEmpty()) {
            log.info("文件为空！");
            return null;
        }
        
        String fileName = file.getOriginalFilename();
        log.info("上传文件: {} - 大小: {}", fileName, file.getSize());

        String ext = getFileExtension(fileName);
        String newFileName = generateUniqueFileName(ext);
        
        return saveFile(file, path, newFileName);
    }
    
    private static String getFileExtension(String fileName) {
        return fileName.substring(fileName.lastIndexOf(".") + 1).toUpperCase();
    }
    
    private static String generateUniqueFileName(String ext) {
        return UUID.randomUUID().toString() + "." + ext;
    }
    
    private static String saveFile(MultipartFile file, String path, String newFileName) {
        File dest = new File(path, newFileName);
        if (!dest.getParentFile().exists()) {
            dest.getParentFile().mkdirs();
        }
        
        try {
            file.transferTo(dest);
            return newFileName;
        } catch (IOException e) {
            log.error("文件保存失败", e);
            return null;
        }
    }
}
