package com.authmatrix.server.proxy;

import com.authmatrix.server.db.DatabaseManager;
import com.authmatrix.server.service.TrafficEventService;
import com.authmatrix.shared.model.TrafficLog;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

@Component
public class ReverseProxyServer {

    private static final Logger log = LoggerFactory.getLogger(ReverseProxyServer.class);
    private static final int MAX_BODY_BYTES = 16384; // 16 KB cap

    private final DatabaseManager databaseManager;
    private final TrafficEventService trafficEventService;
    private HttpServer httpServer;
    private HttpClient httpClient;

    private volatile String targetHost = System.getenv("TARGET_HOST") != null && !System.getenv("TARGET_HOST").isBlank()
            ? System.getenv("TARGET_HOST")
            : "http://localhost:3000";

    private int proxyPort = System.getenv("PROXY_PORT") != null && !System.getenv("PROXY_PORT").isBlank()
            ? Integer.parseInt(System.getenv("PROXY_PORT"))
            : 8080;

    public ReverseProxyServer(DatabaseManager databaseManager, TrafficEventService trafficEventService) {
        this.databaseManager = databaseManager;
        this.trafficEventService = trafficEventService;
    }

    public String getTargetHost() {
        return targetHost;
    }

    public void setTargetHost(String targetHost) {
        if (targetHost == null || targetHost.isBlank()) {
            return;
        }
        String clean = targetHost.trim();
        URI uri = URI.create(clean);
        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new IllegalArgumentException("Only http and https protocols are supported");
        }
        if (clean.endsWith("/")) {
            clean = clean.substring(0, clean.length() - 1);
        }
        this.targetHost = clean;
        log.info("Proxy target host updated to: {}", this.targetHost);
    }

    public int getProxyPort() {
        return proxyPort;
    }

    @PostConstruct
    public void start() {
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        int portToTry = proxyPort;
        boolean bound = false;
        for (int attempt = 0; attempt < 10; attempt++) {
            try {
                httpServer = HttpServer.create(new InetSocketAddress(portToTry), 0);
                httpServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
                httpServer.createContext("/", new ProxyHandler());
                httpServer.start();
                this.proxyPort = portToTry;
                bound = true;
                log.info("Reverse proxy successfully started on port {} forwarding to {}", this.proxyPort, targetHost);
                break;
            } catch (java.net.BindException be) {
                log.warn("Port {} is in use. Attempting next port...", portToTry);
                portToTry++;
            } catch (IOException e) {
                log.error("Failed to start reverse proxy on port {}: {}", portToTry, e.getMessage());
                throw new RuntimeException(e);
            }
        }

        if (!bound) {
            throw new RuntimeException("Could not bind reverse proxy to any port starting from " + proxyPort);
        }
    }

    @PreDestroy
    public void stop() {
        if (httpServer != null) {
            httpServer.stop(1);
            log.info("Reverse proxy stopped");
        }
    }

    private class ProxyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            long startTimeNano = System.nanoTime();
            String method = exchange.getRequestMethod().toUpperCase();
            URI requestUri = exchange.getRequestURI();
            String path = requestUri.getRawPath();
            String query = requestUri.getRawQuery();

            String fullPath = path + (query != null && !query.isBlank() ? "?" + query : "");
            String currentTarget = targetHost;
            String targetUrl = currentTarget + fullPath;

            // Capture request headers
            Headers inHeaders = exchange.getRequestHeaders();
            Map<String, Object> reqHeadersMap = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> entry : inHeaders.entrySet()) {
                if (entry.getValue().size() == 1) {
                    reqHeadersMap.put(entry.getKey(), entry.getValue().get(0));
                } else {
                    reqHeadersMap.put(entry.getKey(), entry.getValue());
                }
            }

            // Capture request body (capped at 16KB)
            byte[] rawReqBody = readBody(exchange.getRequestBody(), MAX_BODY_BYTES);
            String reqBodyString = rawReqBody.length > 0 ? new String(rawReqBody, StandardCharsets.UTF_8) : null;

            // Build forward request
            try {
                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                        .uri(URI.create(targetUrl))
                        .timeout(Duration.ofSeconds(30));

                // Forward headers
                for (Map.Entry<String, List<String>> entry : inHeaders.entrySet()) {
                    String name = entry.getKey();
                    if (isRestrictedHeader(name)) {
                        continue;
                    }
                    for (String val : entry.getValue()) {
                        try {
                            reqBuilder.header(name, val);
                        } catch (Exception ignored) {}
                    }
                }

                // Force accept-encoding = identity to get uncompressed UTF-8
                reqBuilder.setHeader("Accept-Encoding", "identity");

                // Set body publisher
                if (List.of("GET", "HEAD").contains(method)) {
                    reqBuilder.method(method, HttpRequest.BodyPublishers.noBody());
                } else {
                    reqBuilder.method(method, HttpRequest.BodyPublishers.ofByteArray(rawReqBody));
                }

                HttpResponse<byte[]> upstreamRes = httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofByteArray());

                long durationMs = (System.nanoTime() - startTimeNano) / 1_000_000;
                int resStatus = upstreamRes.statusCode();

                // Response headers
                Map<String, Object> resHeadersMap = new LinkedHashMap<>();
                for (Map.Entry<String, List<String>> entry : upstreamRes.headers().map().entrySet()) {
                    String headerName = entry.getKey();
                    if (entry.getValue().size() == 1) {
                        resHeadersMap.put(headerName, entry.getValue().get(0));
                    } else {
                        resHeadersMap.put(headerName, entry.getValue());
                    }
                }

                byte[] resBytes = upstreamRes.body();
                String resBodyString = resBytes.length > 0 ? new String(resBytes, StandardCharsets.UTF_8) : null;

                // Send back to client
                Headers outHeaders = exchange.getResponseHeaders();
                for (Map.Entry<String, List<String>> entry : upstreamRes.headers().map().entrySet()) {
                    String name = entry.getKey();
                    if (isRestrictedResponseHeader(name)) {
                        continue;
                    }
                    for (String val : entry.getValue()) {
                        outHeaders.add(name, val);
                    }
                }

                boolean noBody = (resStatus == 204 || resStatus == 304 || method.equals("HEAD") || resBytes == null || resBytes.length == 0);
                long responseLength = noBody ? -1 : resBytes.length;
                exchange.sendResponseHeaders(resStatus, responseLength);
                if (!noBody) {
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(resBytes);
                    }
                } else {
                    exchange.getResponseBody().close();
                }

                // Record traffic log
                TrafficLog trafficLog = new TrafficLog(
                        UUID.randomUUID().toString(),
                        method,
                        targetUrl,
                        path,
                        reqHeadersMap,
                        reqBodyString,
                        resStatus,
                        resHeadersMap,
                        resBodyString,
                        durationMs,
                        Instant.now().toString()
                );
                databaseManager.insertTrafficLog(trafficLog);
                trafficEventService.broadcast(trafficLog);

            } catch (Exception e) {
                // Return clean 502 Bad Gateway
                long durationMs = (System.nanoTime() - startTimeNano) / 1_000_000;
                log.warn("Proxy forwarding error for {} {}: {}", method, targetUrl, e.getMessage());

                String errorJson = String.format("{\"error\":\"Upstream target unreachable\",\"target\":\"%s\"}", currentTarget);
                byte[] errorBytes = errorJson.getBytes(StandardCharsets.UTF_8);

                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(502, errorBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(errorBytes);
                }

                Map<String, Object> resHeadersMap = Map.of("content-type", "application/json");
                TrafficLog errorLog = new TrafficLog(
                        UUID.randomUUID().toString(),
                        method,
                        targetUrl,
                        path,
                        reqHeadersMap,
                        reqBodyString,
                        502,
                        resHeadersMap,
                        errorJson,
                        durationMs,
                        Instant.now().toString()
                );
                databaseManager.insertTrafficLog(errorLog);
                trafficEventService.broadcast(errorLog);
            }
        }

        private byte[] readBody(InputStream is, int maxBytes) throws IOException {
            if (is == null) return new byte[0];
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int read;
            int total = 0;
            while ((read = is.read(buf)) != -1) {
                int toWrite = Math.min(read, maxBytes - total);
                if (toWrite > 0) {
                    baos.write(buf, 0, toWrite);
                    total += toWrite;
                }
                if (total >= maxBytes) {
                    // Drain remaining stream bytes so HTTP keep-alive connection remains in sync
                    while (is.read(buf) != -1) {
                        // discard remainder
                    }
                    break;
                }
            }
            return baos.toByteArray();
        }

        private static final Set<String> HOP_BY_HOP_HEADERS = Set.of(
                "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                "te", "trailer", "trailers", "transfer-encoding", "upgrade", "host",
                "content-length", "accept-encoding"
        );

        private static final Set<String> HOP_BY_HOP_RESPONSE_HEADERS = Set.of(
                "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                "te", "trailer", "trailers", "transfer-encoding", "upgrade", "content-length"
        );

        private boolean isRestrictedHeader(String name) {
            return HOP_BY_HOP_HEADERS.contains(name.toLowerCase());
        }

        private boolean isRestrictedResponseHeader(String name) {
            return HOP_BY_HOP_RESPONSE_HEADERS.contains(name.toLowerCase());
        }
    }
}
