package top.whgojp.modules.xss.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class XssWebSocketConfig implements WebSocketConfigurer {
    
    @Override
    public void registerWebSocketHandlers(@NonNull WebSocketHandlerRegistry registry) {
        registry.addHandler(new XssWebSocketHandler(), "/xss/websocket")
               .setAllowedOrigins("*"); // 故意允许所有源，用于演示XSS风险
    }
}
