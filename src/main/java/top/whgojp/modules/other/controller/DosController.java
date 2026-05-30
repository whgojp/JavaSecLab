package top.whgojp.modules.other.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.ShearCaptcha;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import top.whgojp.common.utils.R;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * @description 其他漏洞-Dos攻击
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/10/28 23:04
 */
@Slf4j
@Api(value = "DosController", tags = "其他漏洞-Dos攻击")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/other/dos")
public class DosController {
    private final MessageSource messageSource;
    private static final int MAX_IMAGE_WIDTH = 800;
    private static final int MAX_IMAGE_HEIGHT = 300;
    private static final int MAX_IMAGE_PIXELS = 240_000;

    public DosController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @RequestMapping("")
    public String dos() {
        return "vul/other/dos";
    }

    @RequestMapping("/vul")
    public void vul(@RequestParam Integer width, @RequestParam Integer height, HttpServletResponse response) throws IOException {
        response.setContentType("image/jpeg");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache");
        // Captcha parameters are controllable, causing denial of service.
        ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(width, height,4,3);
        try {
            shearCaptcha.write(response.getOutputStream());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @RequestMapping("/safe")
    public void safe(@RequestParam Integer width, @RequestParam Integer height, HttpServletResponse response) throws IOException {
        if (width == null || height == null || width <= 0 || height <= 0
                || width > MAX_IMAGE_WIDTH || height > MAX_IMAGE_HEIGHT
                || (long) width * height > MAX_IMAGE_PIXELS) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write(msg("other.dos.result.imageTooLarge"));
            return;
        }
        response.setContentType("image/jpeg");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache");
        ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(width, height,4,3);
        shearCaptcha.write(response.getOutputStream());
    }

    @RequestMapping("/vul2")
    @ResponseBody
    public R vul2(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return R.error(msg("other.dos.result.chooseZip"));
        }
        File tempFile = null;
        try {
            tempFile = convertMultipartFileToFile(file);
            // Limit decompression depth to 1 to prevent infinite recursion.
            int maxDepth = 1;
            unzip(tempFile, 0, maxDepth);
            return R.ok(msg("other.dos.result.unzipSuccess"));
        } catch (Exception e) {
            e.printStackTrace();
            return R.error(msg("other.dos.result.unzipFailed", e.getMessage()));
        } finally {
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
    }

    private File convertMultipartFileToFile(MultipartFile file) throws IOException {
        // Convert the uploaded MultipartFile to a temporary file.
        File tempFile = File.createTempFile("tempFile", ".zip");
        file.transferTo(tempFile);
        return tempFile;
    }

    private void unzip(File zipFile, int currentDepth, int maxDepth) throws IOException {
        if (currentDepth > maxDepth) {
            throw new IOException(msg("other.dos.result.depthExceeded"));
        }

        try (ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                // Exclude macOS metadata files.
                if (entry.getName().startsWith("__MACOSX") || entry.getName().startsWith("._")) {
                    continue;
                }

                // Recursively decompress ZIP files found inside the archive.
                if (entry.getName().endsWith(".zip")) {
                    // Create a temporary file to store this ZIP.
                    File tempFile = File.createTempFile("unzip", ".zip");
                    try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                        byte[] buffer = new byte[1024];
                        int length;
                        while ((length = zipInputStream.read(buffer)) != -1) {
                            fos.write(buffer, 0, length);
                        }
                    }
                    // Recursively decompress the new ZIP file.
                    unzip(tempFile, currentDepth + 1, maxDepth);
                    // Delete the temporary file after decompression.
                    tempFile.delete();
                } else {
                    // Decompress and store the file.
                    File extractedDir = new File("extracted");
                    if (!extractedDir.exists()) {
                        extractedDir.mkdirs();
                    }
                    File outputFile = new File(extractedDir, entry.getName());
                    try (BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile))) {
                        byte[] buffer = new byte[1024];
                        int length;
                        while ((length = zipInputStream.read(buffer)) != -1) {
                            outputStream.write(buffer, 0, length);
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new IOException(msg("other.dos.result.unzipFileFailed", zipFile.getName()), e);
        }
    }

    private String msg(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }


}
