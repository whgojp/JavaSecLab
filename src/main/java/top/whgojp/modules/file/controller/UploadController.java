package top.whgojp.modules.file.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import top.whgojp.common.utils.CheckUserInput;
import top.whgojp.common.utils.R;
import top.whgojp.common.utils.UploadUtil;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletRequest;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;

/**
 * @description Arbitrary file - upload
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/8 15:57
 */
@Slf4j
@Api(value = "UploadController", tags = "Arbitrary File - Upload")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/file/upload")
public class UploadController {

    @Autowired
    private UploadUtil uploadUtil;
    @Autowired
    private CheckUserInput checkUserInput;
    @Autowired
    private MessageSource messageSource;

    @RequestMapping("")
    public String fileUpload() {
        return "vul/file/upload";
    }

    @ApiOperation(value = "Vulnerable scenario: arbitrary file upload", notes = "Native vulnerable scenario without restrictions")
    @RequestMapping("/vul")
    @ResponseBody
    @SneakyThrows
    public R vul(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
        String suffix = FilenameUtils.getExtension(file.getOriginalFilename());
        String path = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + "/file/";
        String fileUrl = uploadUtil.uploadFileAndReturnUrl(file, suffix, path);
        return R.ok(msg("file.result.uploadSuccess", fileUrl));
    }
    @ApiOperation(value = "Safe code: file upload allowlist", notes = "Check file extensions with an allowlist")
    @RequestMapping("/safe")
    @ResponseBody
    @SneakyThrows
    public R safe(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
        String suffix = FilenameUtils.getExtension(file.getOriginalFilename());
        // Extension allowlist check.
        if (!checkUserInput.checkFileSuffixWhiteList(suffix)){
            return R.error(msg("file.result.uploadImageOnly"));
        }
        if (!isAllowedImageContent(file, suffix)) {
            return R.error(msg("file.result.uploadContentMismatch"));
        }
        String path = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + "/file/";
        String fileUrl = uploadUtil.uploadFileAndReturnUrl(file, suffix, path);
        return R.ok(msg("file.result.uploadSuccess", fileUrl));
    }

    private boolean isAllowedImageContent(MultipartFile file, String suffix) throws IOException {
        String normalizedSuffix = suffix.toLowerCase(Locale.ROOT);
        if ("ico".equals(normalizedSuffix)) {
            try (InputStream inputStream = file.getInputStream()) {
                byte[] header = new byte[4];
                if (inputStream.read(header) != header.length) {
                    return false;
                }
                return header[0] == 0 && header[1] == 0 && header[2] == 1 && header[3] == 0;
            }
        }
        try (InputStream inputStream = file.getInputStream()) {
            BufferedImage image = ImageIO.read(inputStream);
            return image != null;
        } catch (IOException e) {
            log.warn("Image content validation failed: {}", e.getMessage());
            return false;
        }
    }


    // Return the JSP view.
    @GetMapping("/jsp")
    public String showJspPage() {
        return "jsp/test"; // Return the JSP page without path or suffix.
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
