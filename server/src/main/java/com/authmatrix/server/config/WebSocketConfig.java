package com.authmatrix.server.config;

import com.authmatrix.server.websocket.TrafficWebSocketHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final TrafficWebSocketHandler trafficWebSocketHandler;

    public WebSocketConfig(TrafficWebSocketHandler trafficWebSocketHandler) {
        this.trafficWebSocketHandler = trafficWebSocketHandler;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(trafficWebSocketHandler, "/ws/traffic")
                .setAllowedOrigins("*");
    }
}
