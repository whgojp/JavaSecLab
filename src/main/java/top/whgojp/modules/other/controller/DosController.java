package top.whgojp.modules.other.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.ShearCaptcha;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
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
    @RequestMapping("")
    public String dos() {
        return "vul/other/dos";
    }

    @RequestMapping("/vul")
    public void vul(@RequestParam Integer width, @RequestParam Integer height, HttpServletResponse response) throws IOException {
        response.setContentType("image/jpeg");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache");
        // 验证码参数可控 造成拒绝服务攻击
        ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(width, height,4,3);
        try {
            shearCaptcha.write(response.getOutputStream());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    @RequestMapping("/vul2")
    @ResponseBody
    public R vul2(MultipartFile file) {
        try {
            File tempFile = convertMultipartFileToFile(file);
            // 限制解压深度为 1，防止无限递归
            int maxDepth = 1;
            unzip(tempFile, 0, maxDepth);
            return R.ok("文件解压成功!");
        } catch (Exception e) {
            e.printStackTrace();
            return R.error("文件解压失败: " + e.getMessage());
        }
    }

    private File convertMultipartFileToFile(MultipartFile file) throws IOException {
        // 将上传的MultipartFile转换为临时文件
        File tempFile = File.createTempFile("tempFile", ".zip");
        file.transferTo(tempFile);
        return tempFile;
    }

    private void unzip(File zipFile, int currentDepth, int maxDepth) throws IOException {
        if (currentDepth > maxDepth) {
            throw new IOException("超过最大解压深度限制！");
        }

        try (ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                // 排除 macOS 元数据文件
                if (entry.getName().startsWith("__MACOSX") || entry.getName().startsWith("._")) {
                    continue;
                }

                // 如果解压出的文件是ZIP文件，则递归解压
                if (entry.getName().endsWith(".zip")) {
                    // 创建临时文件来存储这个ZIP
                    File tempFile = File.createTempFile("unzip", ".zip");
                    try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                        byte[] buffer = new byte[1024];
                        int length;
                        while ((length = zipInputStream.read(buffer)) != -1) {
                            fos.write(buffer, 0, length);
                        }
                    }
                    // 递归解压这个新的ZIP文件
                    unzip(tempFile, currentDepth + 1, maxDepth);
                    // 解压完成后删除临时文件
                    tempFile.delete();
                } else {
                    // 解压并存储文件
                    File extractedDir = new File("extracted");
                    if (!extractedDir.exists()) {
                        extractedDir.mkdirs();  // 创建目录
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
            throw new IOException("解压文件失败: " + zipFile.getName(), e);
        }
    }


}