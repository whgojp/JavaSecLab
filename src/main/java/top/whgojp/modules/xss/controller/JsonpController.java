package top.whgojp.modules.xss.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/xss")
public class JsonpController {
    
    @GetMapping("/jsonp")
    public String handleJsonp(@RequestParam String callback) {
        // 故意不验证callback参数，直接拼接返回
        return callback + "(" + "{\"message\": \"Hello from JSONP\"}" + ");";
    }
}
