package com.authmatrix.server.service;

import com.authmatrix.shared.model.TrafficLog;
import com.authmatrix.shared.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TrafficEventService {

    private static final Logger log = LoggerFactory.getLogger(TrafficEventService.class);

    private final Set<WebSocketSession> sessions = ConcurrentHashMap.newKeySet();

    public void registerSession(WebSocketSession session) {
        sessions.add(session);
        log.info("WebSocket client connected: {}", session.getId());
    }

    public void removeSession(WebSocketSession session) {
        sessions.remove(session);
        log.info("WebSocket client disconnected: {}", session.getId());
    }

    public void broadcast(TrafficLog trafficLog) {
        if (sessions.isEmpty()) {
            return;
        }

        String json = JsonUtils.toJson(trafficLog);
        TextMessage message = new TextMessage(json);

        for (WebSocketSession session : sessions) {
            if (session.isOpen()) {
                try {
                    synchronized (session) {
                        session.sendMessage(message);
                    }
                } catch (IOException e) {
                    log.warn("Failed to send traffic event to session {}: {}", session.getId(), e.getMessage());
                }
            }
        }
    }
}
