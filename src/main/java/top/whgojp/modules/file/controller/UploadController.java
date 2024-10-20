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
import top.whgojp.common.utils.CheckUserInput;
import top.whgojp.common.utils.R;
import top.whgojp.common.utils.UploadUtil;

import javax.servlet.http.HttpServletRequest;

/**
 * @description 任意文件类-文件上传
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/8 15:57
 */
@Slf4j
@Api(value = "UploadController", tags = "任意文件类-文件上传")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/file/upload")
public class UploadController {

    @Autowired
    private UploadUtil uploadUtil;
    @Autowired
    private CheckUserInput checkUserInput;

    @RequestMapping("")
    public String fileUpload() {
        return "vul/file/upload";
    }

    @ApiOperation(value = "漏洞环境：任意文件上传", notes = "原生漏洞环境，未做任何限制")
    @RequestMapping("/anyFIleUpload")
    @ResponseBody
    @SneakyThrows
    public R vul1AnyFIleUpload(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
        String res;
        String suffix = FilenameUtils.getExtension(file.getOriginalFilename());
        String path = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + "/file/";
        res = uploadUtil.uploadFile(file, suffix, path);
        return R.ok(res);
    }
    @ApiOperation(value = "安全代码：文件上传白名单", notes = "检测文件后缀，做白名单过滤")
    @RequestMapping("/anyFIleUploadWhiteList")
    @ResponseBody
    @SneakyThrows
    public R safe1AnyFIleUploadWhiteList(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
        String res;
        String suffix = FilenameUtils.getExtension(file.getOriginalFilename());
        // 后缀白名单检查
        if (!checkUserInput.checkFileSuffixWhiteList(suffix)){
            return R.error("只能上传图片哦！");
        }
        String path = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + "/file/";
        res = uploadUtil.uploadFile(file, suffix, path);
        return R.ok(res);
    }


    // 返回JSP视图
    @GetMapping("/jsp")
    public String showJspPage() {
        return "jsp/test"; // 返回JSP页面，不包括路径和后缀
    }

}
