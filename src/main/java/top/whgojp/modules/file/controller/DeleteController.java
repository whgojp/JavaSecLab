package top.whgojp.modules.file.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.constant.SysConstant;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @description Arbitrary file - delete
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/8 15:59
 */
@Slf4j
@Api(value = "DeleteController", tags = "Arbitrary File - Delete")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/file/delete")
public class DeleteController {
    @Autowired
    private MessageSource messageSource;

    @RequestMapping("")
    public String fileDelete() {
        return "vul/file/delete";
    }

    @ApiOperation(value = "Vulnerable scenario: arbitrary file delete", notes = "Native vulnerable scenario without restrictions")
    @RequestMapping("/vul")
    @ResponseBody
    @SneakyThrows
    public String vul(@RequestParam("filePath") String filePath) {
        String currentPath = System.getProperty("user.dir");
        log.info("Current path: " + currentPath);
        File file = new File(filePath);
        boolean deleted = false;
        if (file.exists()) {
            deleted = file.delete();
        }
        if (deleted) {
            return msg("file.result.deleteSuccessWithPath", currentPath, filePath);
        } else {
            return msg("file.result.deleteFailedWithPath", currentPath, filePath);
        }
    }

    @Autowired
    private SysConstant sysConstant;
    @ApiOperation(value = "Safe scenario: restricted file delete", notes = "Only allow deleting files from a specific directory")
    @RequestMapping("/safe")
    @ResponseBody
    @SneakyThrows
    public String safe(@RequestParam("fileName") String fileName) {
        String baseDir = sysConstant.getUploadFolder();
        Path basePath = Paths.get(baseDir).toRealPath();
        Path filePath = basePath.resolve(fileName).normalize();
        if (!filePath.startsWith(basePath)) {
            return msg("file.result.accessDeniedPath");
        }
        boolean deleted = false;
        if (Files.isRegularFile(filePath)) {
            Path realFilePath = filePath.toRealPath();
            if (!realFilePath.startsWith(basePath)) {
                return msg("file.result.accessDeniedRealPath");
            }
            deleted = Files.deleteIfExists(filePath);
        }
        if (deleted) {
            return msg("file.result.deleteSuccess", fileName);
        } else {
            return msg("file.result.deleteFailed", fileName);
        }
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
