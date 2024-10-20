package top.whgojp.modules.file.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.var;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import top.whgojp.common.constant.SysConstant;
import top.whgojp.common.utils.CheckUserInput;
import top.whgojp.common.utils.R;
import top.whgojp.common.utils.UploadUtil;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Collectors;

/**
 * @description 任意文件类-文件读取
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/9 17:31
 */
@Slf4j
@Api(value = "ReadController", tags = "任意文件类-文件读取")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/file/read")
public class ReadController {
    @RequestMapping("")
    public String fileRead() {
        return "vul/file/read";
    }


    @ApiOperation(value = "读取文件内容", notes = "读取指定文件的内容")
    @RequestMapping("/readFile")
    @ResponseBody
    public String readFile(@RequestParam("fileName") String fileName) throws IOException {
        String currentPath = System.getProperty("user.dir");
        log.info(currentPath);
        File file = new File(fileName);
        if (file.exists() && file.isFile()) {
            Path filePath = file.toPath();
            // 使用 BufferedReader 和流 API 逐行读取文件
            try (var lines = Files.lines(filePath)) {
                return lines
                        .map(line -> line + "<br/>")
                        .collect(Collectors.joining());
            }
        } else {
            return "当前路径："+currentPath+"<br/>文件不存在或路径不正确：" + fileName;
        }
    }

    @Autowired
    private SysConstant sysConstant;

    @ApiOperation(value = "安全读取文件内容", notes = "仅允许读取特定目录中的文件内容")
    @RequestMapping("/safeReadFile")
    @ResponseBody
    public String safeReadFile(@RequestParam("fileName") String fileName) throws IOException {
        String baseDir = sysConstant.getUploadFolder(); // 限制删除文件所在目录为 /static/upload/下
        Path filePath = Paths.get(baseDir, fileName).normalize(); // 规范化路径
        // 确保文件路径在允许的目录中
        if (!filePath.startsWith(Paths.get(baseDir))) {
            return "访问被拒绝：文件路径不合法";
        }
        File file = filePath.toFile();
        if (file.exists() && file.isFile()) {
            return new String(Files.readAllBytes(file.toPath()));
        } else {
            return "文件不存在或路径不正确：" + fileName;
        }
    }


}
