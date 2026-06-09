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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @description Arbitrary file - read
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/9 17:31
 */
@Slf4j
@Api(value = "ReadController", tags = "Arbitrary File - Read")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/file/read")
public class ReadController {
    @Autowired
    private MessageSource messageSource;

    @RequestMapping("")
    public String fileRead() {
        return "vul/file/read";
    }


    @ApiOperation(value = "Read file content", notes = "Read the specified file content")
    @RequestMapping("/vul")
    @ResponseBody
    public String vul(@RequestParam("fileName") String fileName) throws IOException {
        String currentPath = System.getProperty("user.dir");
        log.info(currentPath);
        File file = new File(fileName);
        if (file.exists() && file.isFile()) {
            Path filePath = file.toPath();
            // Read the file line by line with the stream API.
            try (Stream<String> lines = Files.lines(filePath)) {
                return lines
                        .map(line -> line + "<br/>")
                        .collect(Collectors.joining());
            }
        } else {
            return msg("file.result.readNotFound", currentPath, fileName);
        }
    }

    @Autowired
    private SysConstant sysConstant;

    @ApiOperation(value = "Safely read file content", notes = "Only allow reading files from a specific directory")
    @RequestMapping("/safe")
    @ResponseBody
    public String safe(@RequestParam("fileName") String fileName) throws IOException {
        String baseDir = sysConstant.getUploadFolder();
        Path basePath = Paths.get(baseDir).toRealPath();
        Path filePath = basePath.resolve(fileName).normalize();
        // Normalize the path first, then ensure the target file remains inside the allowed directory.
        if (!filePath.startsWith(basePath)) {
            return msg("file.result.accessDeniedPath");
        }
        if (Files.isRegularFile(filePath)) {
            Path realFilePath = filePath.toRealPath();
            if (!realFilePath.startsWith(basePath)) {
                return msg("file.result.accessDeniedRealPath");
            }
            return new String(Files.readAllBytes(realFilePath));
        } else {
            return msg("file.result.fileNotFound", fileName);
        }
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
