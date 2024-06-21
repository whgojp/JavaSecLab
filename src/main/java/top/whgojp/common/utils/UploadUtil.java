package top.whgojp.common.utils;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import top.whgojp.Application;

import java.io.File;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * @description 文件上传工具类
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/23 15:02
 */
@Component
public class UploadUtil {
    @Value("${server.port:8080}")
    String port;
//    @SneakyThrows
//    public static String getUploadDir() {
//        String path = Application.class.getProtectionDomain().getCodeSource().getLocation().getPath();//这个class是启动类，这里自行修改
//        path = URLDecoder.decode(path, StandardCharsets.UTF_8.toString());
//        if (System.getProperty("os.name").contains("Windows")) {
//            int firstIndex = path.indexOf("/");
//            path = path.substring(firstIndex+1);
//        }
//        if (path.contains("jar")) {
//            path = path.substring(0, path.lastIndexOf("."));
//        }
//        path = path.replace("target/classes/", "");
//        int lastIndex = path.lastIndexOf("/");
//        path = path.substring(0,lastIndex);
//        String url = path + "/upload";
//        File uploadDirectory = new File(url);
//        if (!uploadDirectory.exists()) {
//            uploadDirectory.mkdir(); // 创建目录
//        }
//        return url;
//    }
//
//    public static final String UPLOAD_DIR = getUploadDir();
//
//    @SneakyThrows
//    public static String uploadFile(MultipartFile file){
//        String filePah = UPLOAD_DIR;
//        String originalFilename = file.getOriginalFilename();
//        String fileExtension = getFileExtension(originalFilename);
////在扩展名限制文件，如果不想限制直接去除即可
//        if (isValidFileExtension(fileExtension)) {
//            File destFile = new File(filePah + File.separator + originalFilename);
//            file.transferTo(destFile);
//            String fileUrl = filePah + '\\' + originalFilename;
//            return fileUrl;
//        } else {
////            throw new ProjectException(MessageEnum.PAK_ERR.getCode(),MessageEnum.PAK_ERR.getMessage());
//        }
//    }
//
//    //提取扩展名
//    private static String getFileExtension(String filename) {
//        int dotIndex = filename.lastIndexOf(".");
//        if (dotIndex > 0 && dotIndex < filename.length() - 1) {
//            return filename.substring(dotIndex + 1).toLowerCase();
//        }
//        return "";
//    }
//    //限制文件
//    private static boolean isValidFileExtension(String fileExtensions) {
//        List<String> allowedExtensions = Arrays.asList("","");//文件类别
//        return Arrays.stream(fileExtensions)
//                .allMatch(allowedExtensions::contains);
//    }
//}

}
