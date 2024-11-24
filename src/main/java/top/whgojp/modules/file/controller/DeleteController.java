package top.whgojp.modules.file.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
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

/**
 * @description 任意文件类-文件删除
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/8 15:59
 */
@Slf4j
@Api(value = "DeleteController", tags = "任意文件类-文件删除")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/file/delete")
public class DeleteController {
    @RequestMapping("")
    public String fileDelete() {
        return "vul/file/delete";
    }

    @ApiOperation(value = "漏洞场景：任意文件删除", notes = "原生漏洞场景，未做任何限制")
    @RequestMapping("/vul")
    @ResponseBody
    @SneakyThrows
    public String vul(@RequestParam("filePath") String filePath) {
        String currentPath = System.getProperty("user.dir");
        log.info("当前路径："+currentPath);
        File file = new File(filePath);
        boolean deleted = false;
        if (file.exists()) {
            deleted = file.delete();
        }
        if (deleted) {
            return "当前路径:"+currentPath+"<br/>文件删除成功: " + filePath;
        } else {
            return "当前路径:"+currentPath+"<br/>文件删除失败或文件不存在: " + filePath;
        }
    }

    @Autowired
    private SysConstant sysConstant;
    @ApiOperation(value = "安全场景：限制文件删除", notes = "仅允许删除特定目录中的文件")
    @RequestMapping("/safe")
    @ResponseBody
    @SneakyThrows
    public String safe(@RequestParam("fileName") String fileName) {
        String baseDir = sysConstant.getUploadFolder(); // 限制删除文件所在目录为 /static/upload/下
        File file = new File(baseDir, fileName);
        boolean deleted = false;
        if (file.exists() && file.getCanonicalPath().startsWith(new File(baseDir).getCanonicalPath())) {
            deleted = file.delete();
        }
        if (deleted) {
            return "文件删除成功: " + fileName;
        } else {
            return "文件删除失败或文件不存在: " + fileName;
        }
    }


}
