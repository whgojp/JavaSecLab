package top.whgojp.modules.xss.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import top.whgojp.common.utils.R;
import cn.hutool.core.date.DateUtil;

import java.io.File;
import java.io.IOException;

/**
 * @description 跨站脚本-其他场景
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/5/23 13:59
 */
@Slf4j
@Api(value = "OtherController", tags = "跨站脚本-其他场景")
@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/xss/other")
public class OtherController {
    @Autowired
    private ResourceLoader resourceLoader;

    // 文件上传接口
    @ApiOperation(value = "漏洞环境：文件上传导致存储XSS", notes = "原生漏洞环境,未加任何过滤，Controller接口返回Json类型结果")
    @PostMapping("/a-vul1-upload")
    public R vul1Upload(@RequestParam("file") MultipartFile file) {

        try {
            String originalFilename = file.getOriginalFilename();
            String suffix = originalFilename.substring(originalFilename.lastIndexOf("."));

            String uploadFolder = resourceLoader.getResource("classpath:static/upload/xss/").getFile().getPath();
            String fileName = +DateUtil.current() + suffix;
            String newFilePath = uploadFolder + "/"+fileName;

            file.transferTo(new File(newFilePath)); // 将文件保存到指定路径
            log.info("上传文件成功，文件路径：" + newFilePath);
            return R.ok("上传文件成功，文件路径：" + "http://127.0.0.1:8080/file/"+fileName);
        } catch (IOException e) {
            e.printStackTrace(); // 打印异常堆栈信息
            log.info("文件上传失败" + e.getMessage());
            return R.error("文件上传失败" + e.getMessage());
        }
    }

}
