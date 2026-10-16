package com.authmatrix.server.controller;

import com.authmatrix.server.db.DatabaseManager;
import com.authmatrix.server.proxy.ReverseProxyServer;
import com.authmatrix.server.service.WebhookDispatcher;
import com.authmatrix.server.verifier.MatrixVerifier;
import com.authmatrix.shared.model.*;
import com.authmatrix.shared.util.*;
import com.fasterxml.jackson.core.type.TypeReference;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
public class ApiController {

    private final DatabaseManager databaseManager;
    private final ReverseProxyServer proxyServer;
    private final MatrixVerifier matrixVerifier;
    private final WebhookDispatcher webhookDispatcher;
    private final HttpClient httpClient;

    public ApiController(DatabaseManager databaseManager,
                         ReverseProxyServer proxyServer,
                         MatrixVerifier matrixVerifier,
                         WebhookDispatcher webhookDispatcher) {
        this.databaseManager = databaseManager;
        this.proxyServer = proxyServer;
        this.matrixVerifier = matrixVerifier;
        this.webhookDispatcher = webhookDispatcher;
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    // ============================================================
    // CONFIGURATION
    // ============================================================

    @GetMapping("/config")
    public Map<String, Object> getConfig() {
        return Map.of(
                "targetHost", proxyServer.getTargetHost(),
                "proxyPort", proxyServer.getProxyPort()
        );
    }

    @PutMapping("/config")
    public ResponseEntity<?> updateConfig(@RequestBody Map<String, String> body) {
        String targetHost = body.get("targetHost");
        if (targetHost == null || targetHost.isBlank()) {
            targetHost = body.get("target_base_url");
        }
        if (targetHost == null || targetHost.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "targetHost is required"));
        }
        try {
            URI uri = URI.create(targetHost.trim());
            if (uri.getScheme() == null || uri.getHost() == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid URL scheme or host"));
            }
            String scheme = uri.getScheme().toLowerCase();
            if (!scheme.equals("http") && !scheme.equals("https")) {
                return ResponseEntity.badRequest().body(Map.of("error", "Only http and https protocols are supported"));
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid targetHost URL: " + e.getMessage()));
        }

        proxyServer.setTargetHost(targetHost.trim());
        return ResponseEntity.ok(Map.of(
                "targetHost", proxyServer.getTargetHost(),
                "proxyPort", proxyServer.getProxyPort()
        ));
    }

    // ============================================================
    // TRAFFIC HISTORY
    // ============================================================

    @GetMapping("/traffic")
    public List<TrafficLog> getTraffic(@RequestParam(defaultValue = "500") int limit) {
        return databaseManager.listTrafficLogs(limit);
    }

    @DeleteMapping("/traffic")
    public Map<String, Boolean> clearTraffic() {
        databaseManager.clearTrafficLogs();
        return Map.of("cleared", true);
    }

    // ============================================================
    // ROLES
    // ============================================================

    @GetMapping("/roles")
    public List<Role> getRoles() {
        return databaseManager.listRoles();
    }

    @PostMapping("/roles")
    public ResponseEntity<?> createOrUpdateRole(@Valid @RequestBody CreateRoleInput input) {
        Role role = databaseManager.upsertRole(input);
        return ResponseEntity.ok(role);
    }

    @DeleteMapping("/roles/{id}")
    public Map<String, Boolean> deleteRole(@PathVariable String id) {
        databaseManager.deleteRole(id);
        return Map.of("deleted", true);
    }

    @DeleteMapping("/roles")
    public Map<String, Boolean> clearRoles() {
        databaseManager.clearRoles();
        return Map.of("cleared", true);
    }

    // ============================================================
    // POLICIES & ENDPOINTS
    // ============================================================

    @GetMapping({"/policies", "/endpoints"})
    public List<EndpointPolicy> getPolicies() {
        return databaseManager.listEndpoints();
    }

    @PostMapping({"/policies", "/endpoints"})
    public ResponseEntity<?> createPolicy(@Valid @RequestBody CreateEndpointPolicyInput input) {
        EndpointPolicy endpoint = databaseManager.createEndpoint(input);
        return ResponseEntity.ok(endpoint);
    }

    @PutMapping({"/policies/{id}", "/endpoints/{id}"})
    public ResponseEntity<?> updatePolicy(@PathVariable String id, @Valid @RequestBody CreateEndpointPolicyInput input) {
        EndpointPolicy updated = databaseManager.updateEndpoint(id, input);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping({"/policies/{id}", "/endpoints/{id}"})
    public Map<String, Boolean> deletePolicy(@PathVariable String id) {
        databaseManager.deleteEndpoint(id);
        return Map.of("deleted", true);
    }

    @DeleteMapping({"/policies", "/endpoints"})
    public Map<String, Boolean> clearPolicies() {
        databaseManager.clearEndpoints();
        return Map.of("cleared", true);
    }

    // ============================================================
    // OPENAPI / SWAGGER SPEC IMPORTER
    // ============================================================

    @PostMapping("/spec/import")
    public ResponseEntity<?> importOpenApiSpec(@RequestBody Map<String, String> body) {
        String specContent = body.get("spec");
        if (specContent == null || specContent.isBlank()) {
            specContent = body.get("content");
        }
        if (specContent == null || specContent.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Spec content is required ('spec' or 'content' field)"));
        }

        try {
            List<Role> existingRoles = databaseManager.listRoles();
            List<String> roleNames = existingRoles.stream().map(Role::getName).toList();

            OpenApiImporter.ImportResult result = OpenApiImporter.parseSpec(specContent, roleNames);

            if (result.detectedTargetBaseUrl() != null && !result.detectedTargetBaseUrl().isBlank()) {
                try {
                    URI uri = URI.create(result.detectedTargetBaseUrl());
                    if (uri.getScheme() != null && (uri.getScheme().equalsIgnoreCase("http") || uri.getScheme().equalsIgnoreCase("https"))) {
                        proxyServer.setTargetHost(result.detectedTargetBaseUrl());
                    }
                } catch (Exception ignored) {}
            }

            int count = 0;
            for (CreateEndpointPolicyInput epInput : result.endpoints()) {
                databaseManager.createEndpoint(epInput);
                count++;
            }

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "importedCount", count,
                    "specVersion", result.specVersion(),
                    "title", result.title(),
                    "targetBaseUrl", proxyServer.getTargetHost()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Failed to import OpenAPI spec: " + e.getMessage()));
        }
    }

    // ============================================================
    // REPEATER SERVICE
    // ============================================================

    @PostMapping("/repeater/send")
    public ResponseEntity<?> sendRepeaterRequest(@RequestBody Map<String, Object> body) {
        String method = (String) body.getOrDefault("method", "GET");
        String url = (String) body.get("url");
        if (url == null || url.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "url is required"));
        }

        try {
            URI uri = URI.create(url.trim());
            if (uri.getScheme() == null || uri.getHost() == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid URL format"));
            }
            String scheme = uri.getScheme().toLowerCase();
            if (!scheme.equals("http") && !scheme.equals("https")) {
                return ResponseEntity.badRequest().body(Map.of("error", "Only http and https protocols are supported"));
            }

            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                    .uri(uri)
                    .timeout(Duration.ofSeconds(15));

            Object headersObj = body.get("headers");
            if (headersObj instanceof Map<?, ?> headersMap) {
                for (Map.Entry<?, ?> entry : headersMap.entrySet()) {
                    String name = String.valueOf(entry.getKey());
                    String value = String.valueOf(entry.getValue());
                    if (isRestrictedClientHeader(name)) continue;
                    try {
                        reqBuilder.header(name, value);
                    } catch (Exception ignored) {}
                }
            }

            String bodyContent = (String) body.get("body");
            String upperMethod = method.toUpperCase();
            if (List.of("GET", "HEAD", "OPTIONS").contains(upperMethod) || bodyContent == null || bodyContent.isEmpty()) {
                reqBuilder.method(upperMethod, HttpRequest.BodyPublishers.noBody());
            } else {
                reqBuilder.method(upperMethod, HttpRequest.BodyPublishers.ofString(bodyContent, StandardCharsets.UTF_8));
            }

            long startTime = System.nanoTime();
            HttpResponse<byte[]> response = httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofByteArray());
            long durationMs = (System.nanoTime() - startTime) / 1_000_000;

            byte[] resBytes = response.body();
            String resBodyStr = resBytes != null && resBytes.length > 0 ? new String(resBytes, StandardCharsets.UTF_8) : "";

            Map<String, String> resHeaders = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> h : response.headers().map().entrySet()) {
                resHeaders.put(h.getKey(), String.join(", ", h.getValue()));
            }

            int status = response.statusCode();
            String statusText = getHttpStatusText(status);

            return ResponseEntity.ok(Map.of(
                    "status", status,
                    "response_status", status,
                    "statusText", statusText,
                    "headers", resHeaders,
                    "response_headers", resHeaders,
                    "body", resBodyStr,
                    "response_body", resBodyStr,
                    "duration_ms", durationMs,
                    "size", resBytes != null ? resBytes.length : 0,
                    "contentType", resHeaders.getOrDefault("content-type", "text/plain")
            ));

        } catch (Exception e) {
            return ResponseEntity.ok(Map.of(
                    "status", 0,
                    "response_status", 0,
                    "statusText", "Error: " + e.getMessage(),
                    "headers", Collections.emptyMap(),
                    "body", "Connection error: " + e.getMessage(),
                    "duration_ms", 0,
                    "size", 0
            ));
        }
    }

    private boolean isRestrictedClientHeader(String name) {
        String lower = name.toLowerCase();
        return lower.equals("host") || lower.equals("content-length") || lower.equals("connection")
                || lower.equals("upgrade") || lower.equals("transfer-encoding") || lower.equals("te");
    }

    private String getHttpStatusText(int status) {
        return switch (status) {
            case 200 -> "200 OK";
            case 201 -> "201 Created";
            case 204 -> "204 No Content";
            case 301 -> "301 Moved Permanently";
            case 302 -> "302 Found";
            case 304 -> "304 Not Modified";
            case 400 -> "400 Bad Request";
            case 401 -> "401 Unauthorized";
            case 403 -> "403 Forbidden";
            case 404 -> "404 Not Found";
            case 405 -> "405 Method Not Allowed";
            case 409 -> "409 Conflict";
            case 422 -> "422 Unprocessable Entity";
            case 429 -> "429 Too Many Requests";
            case 500 -> "500 Internal Server Error";
            case 502 -> "502 Bad Gateway";
            case 503 -> "503 Service Unavailable";
            case 504 -> "504 Gateway Timeout";
            default -> status + " HTTP Response";
        };
    }

    // ============================================================
    // MATRIX RUN & RESULTS
    // ============================================================

    @GetMapping("/matrix/results")
    public DatabaseManager.MatrixRunResult getLatestMatrixResults() {
        return databaseManager.getLatestMatrixResults();
    }

    @PostMapping(value = "/matrix/run")
    public DatabaseManager.MatrixRunResult runMatrix(@RequestBody(required = false) String rawBody) {
        Integer timeoutMs = null;
        String targetHost = proxyServer.getTargetHost();

        if (rawBody != null && !rawBody.isBlank()) {
            try {
                Map<String, Object> body = JsonUtils.getJsonMapper().readValue(rawBody, new TypeReference<Map<String, Object>>() {});
                if (body != null) {
                    if (body.containsKey("timeoutMs")) {
                        timeoutMs = ((Number) body.get("timeoutMs")).intValue();
                    }
                    if (body.containsKey("target_base_url")) {
                        String t = (String) body.get("target_base_url");
                        if (t != null && !t.isBlank()) targetHost = t;
                    } else if (body.containsKey("targetHost")) {
                        String t = (String) body.get("targetHost");
                        if (t != null && !t.isBlank()) targetHost = t;
                    }
                }
            } catch (Exception ignored) {}
        }

        return matrixVerifier.evaluateMatrix(
                targetHost,
                databaseManager.listEndpoints(),
                databaseManager.listRoles(),
                timeoutMs
        );
    }

    // ============================================================
    // EXECUTIVE REPORTS (SARIF, HTML, MARKDOWN)
    // ============================================================

    @GetMapping(value = "/reports/sarif", produces = "application/json")
    public ResponseEntity<String> getSarifReport() {
        DatabaseManager.MatrixRunResult runResult = databaseManager.getLatestMatrixResults();
        String sarifJson = SarifReportGenerator.generateSarif(
                runResult.runId(),
                runResult.results(),
                proxyServer.getTargetHost()
        );
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"authmatrix-findings.sarif\"")
                .body(sarifJson);
    }

    @GetMapping(value = "/reports/html", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> getHtmlReport() {
        DatabaseManager.MatrixRunResult runResult = databaseManager.getLatestMatrixResults();
        String html = HtmlReportGenerator.generateHtml(
                runResult.runId(),
                runResult.results(),
                proxyServer.getTargetHost()
        );
        return ResponseEntity.ok(html);
    }

    @GetMapping(value = "/reports/markdown", produces = "text/markdown")
    public ResponseEntity<String> getMarkdownReport() {
        DatabaseManager.MatrixRunResult runResult = databaseManager.getLatestMatrixResults();
        String md = MarkdownReportGenerator.generateMarkdown(
                runResult.runId(),
                runResult.results(),
                proxyServer.getTargetHost()
        );
        return ResponseEntity.ok(md);
    }

    // ============================================================
    // WEBHOOK ALERTS
    // ============================================================

    @GetMapping("/webhook/config")
    public WebhookConfig getWebhookConfig() {
        return databaseManager.getWebhookConfig();
    }

    @PostMapping("/webhook/config")
    public ResponseEntity<?> saveWebhookConfig(@RequestBody WebhookConfig config) {
        databaseManager.saveWebhookConfig(config);
        return ResponseEntity.ok(config);
    }

    @PostMapping("/webhook/test")
    public ResponseEntity<?> testWebhook() {
        WebhookConfig config = databaseManager.getWebhookConfig();
        if (config.getWebhookUrl() == null || config.getWebhookUrl().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "No webhook URL configured"));
        }

        DatabaseManager.MatrixRunResult runResult = databaseManager.getLatestMatrixResults();
        boolean sent = webhookDispatcher.dispatchAlert(
                config,
                runResult.runId() != null ? runResult.runId() : "test-run-001",
                proxyServer.getTargetHost(),
                runResult.results()
        );

        return ResponseEntity.ok(Map.of("success", sent, "url", config.getWebhookUrl()));
    }

    // ============================================================
    // CONFIG / YAML EXPORT & IMPORT
    // ============================================================

    @GetMapping({"/config/export", "/yaml/export"})
    public Map<String, Object> exportConfig() {
        List<Role> roles = databaseManager.listRoles();
        Map<String, AuthMatrixYaml.YamlRole> roleMap = new LinkedHashMap<>();
        for (Role r : roles) {
            roleMap.put(r.getName(), new AuthMatrixYaml.YamlRole(
                    r.getHeaderName(),
                    r.getHeaderValue(),
                    r.getAuthHandler(),
                    r.getParams()
            ));
        }

        List<EndpointPolicy> endpoints = databaseManager.listEndpoints();
        List<AuthMatrixYaml.YamlEndpoint> endpointList = new ArrayList<>();
        for (EndpointPolicy ep : endpoints) {
            endpointList.add(new AuthMatrixYaml.YamlEndpoint(
                    ep.getName(),
                    ep.getMethod(),
                    ep.getPath(),
                    ep.getHeaders(),
                    ep.getBody(),
                    ep.getExpect(),
                    ep.getAssertions()
            ));
        }

        AuthMatrixYaml yamlObj = new AuthMatrixYaml("1.0", proxyServer.getTargetHost(), roleMap, endpointList);
        String yamlStr = JsonUtils.toYaml(yamlObj);
        return Map.of(
                "yaml", yamlStr,
                "config", yamlObj
        );
    }

    @PostMapping({"/config/import", "/yaml/import"})
    public ResponseEntity<?> importConfig(@RequestBody Map<String, String> body) {
        String content = body.get("content");
        if (content == null || content.isBlank()) {
            content = body.get("yaml");
        }
        if (content == null || content.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "content or yaml field is required"));
        }

        try {
            AuthMatrixYaml yamlObj;
            if (content.trim().startsWith("{")) {
                yamlObj = JsonUtils.fromJson(content, AuthMatrixYaml.class);
            } else {
                yamlObj = JsonUtils.fromYaml(content);
            }

            if (yamlObj.getTargetBaseUrl() != null && !yamlObj.getTargetBaseUrl().isBlank()) {
                try {
                    URI targetUri = URI.create(yamlObj.getTargetBaseUrl().trim());
                    String scheme = targetUri.getScheme() != null ? targetUri.getScheme().toLowerCase() : "";
                    if (scheme.equals("http") || scheme.equals("https")) {
                        proxyServer.setTargetHost(yamlObj.getTargetBaseUrl().trim());
                    }
                } catch (Exception ignored) {}
            }

            int importedRoles = 0;
            if (yamlObj.getRoles() != null) {
                for (Map.Entry<String, AuthMatrixYaml.YamlRole> entry : yamlObj.getRoles().entrySet()) {
                    String roleName = entry.getKey();
                    AuthMatrixYaml.YamlRole r = entry.getValue();
                    databaseManager.upsertRole(new CreateRoleInput(
                            roleName,
                            r.getHeaderName() != null ? r.getHeaderName() : "Authorization",
                            r.getHeaderValue() != null ? r.getHeaderValue() : "",
                            r.getAuthHandler(),
                            r.getParams()
                    ));
                    importedRoles++;
                }
            }

            int importedEndpoints = 0;
            if (yamlObj.getEndpoints() != null) {
                for (AuthMatrixYaml.YamlEndpoint ep : yamlObj.getEndpoints()) {
                    String bodyStr = null;
                    if (ep.getBody() != null) {
                        if (ep.getBody() instanceof String s) {
                            bodyStr = s;
                        } else {
                            bodyStr = JsonUtils.toJson(ep.getBody());
                        }
                    }
                    databaseManager.createEndpoint(new CreateEndpointPolicyInput(
                            ep.getName(),
                            ep.getMethod(),
                            ep.getPath(),
                            ep.getHeaders(),
                            bodyStr,
                            ep.getExpect(),
                            ep.getAssertions()
                    ));
                    importedEndpoints++;
                }
            }

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "importedRoles", importedRoles,
                    "importedEndpoints", importedEndpoints,
                    "targetHost", proxyServer.getTargetHost()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Failed to parse configuration: " + e.getMessage()));
        }
    }

    // ============================================================
    // AUTHMATRIX PRO DECODER UTILITY SERVICE
    // ============================================================

    @PostMapping("/decoder")
    public ResponseEntity<?> decodeOrEncode(@RequestBody Map<String, String> body) {
        String input = body.getOrDefault("input", "");
        String action = body.getOrDefault("action", "url_decode").toLowerCase();

        try {
            String result = switch (action) {
                case "url_encode" -> URLEncoder.encode(input, StandardCharsets.UTF_8);
                case "url_decode" -> URLDecoder.decode(input, StandardCharsets.UTF_8);
                case "base64_encode" -> Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
                case "base64_decode" -> new String(Base64.getDecoder().decode(input.trim()), StandardCharsets.UTF_8);
                case "hex_encode" -> bytesToHex(input.getBytes(StandardCharsets.UTF_8));
                case "hex_decode" -> new String(hexToBytes(input.replaceAll("\\s+", "")), StandardCharsets.UTF_8);
                case "md5" -> hashString(input, "MD5");
                case "sha1" -> hashString(input, "SHA-1");
                case "sha256" -> hashString(input, "SHA-256");
                case "jwt_decode" -> decodeJwt(input);
                default -> "Unknown action: " + action;
            };

            return ResponseEntity.ok(Map.of("result", result, "action", action));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage(), "action", action));
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int d1 = Character.digit(hex.charAt(i), 16);
            int d2 = Character.digit(hex.charAt(i + 1), 16);
            if (d1 == -1 || d2 == -1) {
                throw new IllegalArgumentException("Invalid hexadecimal character in string");
            }
            data[i / 2] = (byte) ((d1 << 4) + d2);
        }
        return data;
    }

    private String hashString(String input, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(digest);
    }

    private String decodeJwt(String token) {
        String[] parts = token.trim().split("\\.");
        if (parts.length < 2) {
            return "Invalid JWT token structure (requires at least header.payload)";
        }
        try {
            String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            String signature = parts.length > 2 ? parts[2] : "";

            return "HEADER:\n" + header + "\n\nPAYLOAD:\n" + payload + "\n\nSIGNATURE:\n" + signature;
        } catch (Exception e) {
            return "Failed to decode JWT: " + e.getMessage();
        }
    }
}
