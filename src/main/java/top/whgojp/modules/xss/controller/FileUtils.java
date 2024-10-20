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
import java.util.Random;

/**
 * 功能 : 上传文件工具类
 * 创建人 : 慌途L
 */
@Slf4j
public class FileUtils {

    public static String upLoadFile(MultipartFile file, String path) {

        if(file.isEmpty()){
            log.info("文件为空！");
            return null;
        }
        String fileName = file.getOriginalFilename();
        int size = (int) file.getSize();
        log.info(fileName + "-->" + size);

        // 取得文件的后缀名。
        String ext = fileName.substring(fileName.lastIndexOf(".") + 1).toUpperCase();

        String newFileName =
                System.currentTimeMillis() / 1000 + new Random().nextInt(100000)+"." + ext;

        //String path = "F:/test" ;
        File dest = new File(path + "/" + newFileName);
        if(!dest.getParentFile().exists()){ //判断文件父目录是否存在
            dest.getParentFile().mkdir();
        }
        try {
            file.transferTo(dest); //保存文件
            return newFileName;
        } catch (IllegalStateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
}

