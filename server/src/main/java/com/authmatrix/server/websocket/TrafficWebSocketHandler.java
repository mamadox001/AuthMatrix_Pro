package com.authmatrix.server.websocket;

import com.authmatrix.server.service.TrafficEventService;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

@Component
public class TrafficWebSocketHandler extends TextWebSocketHandler {

    private final TrafficEventService trafficEventService;

    public TrafficWebSocketHandler(TrafficEventService trafficEventService) {
        this.trafficEventService = trafficEventService;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        trafficEventService.registerSession(session);
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        trafficEventService.removeSession(session);
    }
}
