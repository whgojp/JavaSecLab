package top.whgojp.modules.file.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.apache.log4j.lf5.util.StreamUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.constant.SysConstant;


import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @description Arbitrary file - download
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/8 15:59
 */
@Slf4j
@Api(value = "DownloadController", tags = "Arbitrary File - Download")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/file/download")
public class DownloadController {
    @Autowired
    private MessageSource messageSource;

    @RequestMapping("")
    public String fileDownload() {
        return "vul/file/download";
    }

    @ApiOperation(value = "Download file", notes = "Download the specified file")
    @RequestMapping("/vul")
    public void vul(@RequestParam("fileName") String fileName, HttpServletResponse response) throws IOException {
        File file = new File(fileName);

        if (file.exists() && file.isFile()) {
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"");
            try (FileInputStream fis = new FileInputStream(file);
                 OutputStream os = response.getOutputStream()) {
                StreamUtils.copy(fis, os);
                os.flush();
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, msg("file.result.downloadNotFound", fileName));
        }
    }

    @Autowired
    private SysConstant sysConstant;
    @RequestMapping("/safe")
    public void safe(@RequestParam("fileName") String fileName, HttpServletResponse response) throws IOException {
        String baseDir = sysConstant.getUploadFolder();
        if (!isValidFileName(fileName)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, msg("file.result.invalidFileName", fileName));
            return;
        }
        Path basePath = Paths.get(baseDir).toRealPath();
        Path filePath = basePath.resolve(fileName).normalize();
        if (filePath.startsWith(basePath) && Files.isRegularFile(filePath)) {
            Path realFilePath = filePath.toRealPath();
            if (!realFilePath.startsWith(basePath)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, msg("file.result.invalidRealPath", fileName));
                return;
            }
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + realFilePath.getFileName().toString() + "\"");
            try (InputStream fis = Files.newInputStream(realFilePath);
                 OutputStream os = response.getOutputStream()) {
                StreamUtils.copy(fis, os);
                os.flush();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, msg("file.result.downloadNotAccessible", fileName));
        }
    }

    private boolean isValidFileName(String fileName) {
        return fileName != null && fileName.matches("^[\\w,\\s-]+\\.[A-Za-z]{3,4}$");
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
