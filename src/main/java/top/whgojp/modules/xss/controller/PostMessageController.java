package top.whgojp.modules.xss.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/xss/postmessage")
public class PostMessageController {
    
    @GetMapping("/sender")
    public String sender() {
        return "vul/xss/postmessage/sender";
    }

    @GetMapping("/receiver")
    public String receiver() {
        return "vul/xss/postmessage/receiver";
    }
}
