package com.authmatrix.server.verifier;

import com.authmatrix.server.db.DatabaseManager;
import com.authmatrix.server.service.WebhookDispatcher;
import com.authmatrix.shared.model.*;
import com.authmatrix.shared.util.JsonUtils;
import com.authmatrix.shared.util.RemediationAdvisor;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class MatrixVerifier {

    private static final Logger log = LoggerFactory.getLogger(MatrixVerifier.class);

    private final DatabaseManager databaseManager;
    private final WebhookDispatcher webhookDispatcher;
    private final HttpClient httpClient;

    private static final Pattern PARAM_PATTERN = Pattern.compile("\\{([A-Za-z0-9_-]+)\\}");

    public MatrixVerifier(DatabaseManager databaseManager, WebhookDispatcher webhookDispatcher) {
        this.databaseManager = databaseManager;
        this.webhookDispatcher = webhookDispatcher;
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public DatabaseManager.MatrixRunResult evaluateMatrix(String targetBaseUrl,
                                                          List<EndpointPolicy> endpoints,
                                                          List<Role> roles,
                                                          Integer timeoutMs) {
        String runId = UUID.randomUUID().toString();
        List<MatrixResult> results = new ArrayList<>();
        int timeout = timeoutMs != null && timeoutMs > 0 ? timeoutMs : 10000;

        String baseUrl = targetBaseUrl != null ? targetBaseUrl.trim() : "";
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
            throw new IllegalArgumentException("Target base URL must use http or https scheme");
        }

        // 1. Auto-refresh dynamic tokens for roles with auth_handlers configured
        for (Role role : roles) {
            refreshRoleTokenIfNecessary(role, baseUrl);
        }

        // 2. Perform matrix evaluation
        for (EndpointPolicy endpoint : endpoints) {
            for (Role role : roles) {
                int expectedStatus = endpoint.getExpect().getOrDefault(role.getName(), 200);

                // Build request headers
                Map<String, String> requestHeaders = new HashMap<>(endpoint.getHeaders() != null ? endpoint.getHeaders() : Collections.emptyMap());
                requestHeaders.put("Accept", "application/json");

                String body = endpoint.getBody();
                if (body != null && !body.isBlank()) {
                    requestHeaders.putIfAbsent("Content-Type", "application/json");
                }

                if (role.getHeaderValue() != null && !role.getHeaderValue().trim().isEmpty()) {
                    requestHeaders.put(role.getHeaderName(), role.getHeaderValue());
                } else {
                    requestHeaders.remove(role.getHeaderName());
                }

                // Resolve path parameters for this role
                String cleanPath = endpoint.getPath().startsWith("/") ? endpoint.getPath() : "/" + endpoint.getPath();
                String resolvedPath = resolvePathParams(cleanPath, role.getParams());
                String targetUrl = baseUrl + resolvedPath;

                long startTime = System.nanoTime();
                int actualStatus = 0;
                long responseBytes = 0;
                Verdict verdict = Verdict.PASS;
                String errorMessage = null;
                String assertionFailure = null;
                boolean bolaDetected = false;
                byte[] resBody = null;

                try {
                    HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                            .uri(URI.create(targetUrl))
                            .timeout(Duration.ofMillis(timeout));

                    for (Map.Entry<String, String> entry : requestHeaders.entrySet()) {
                        String hName = entry.getKey();
                        if (isRestrictedHeader(hName)) continue;
                        try {
                            reqBuilder.header(hName, entry.getValue());
                        } catch (Exception ignored) {}
                    }

                    HttpMethod method = endpoint.getMethod();
                    if (method == HttpMethod.GET || method == HttpMethod.HEAD) {
                        reqBuilder.method(method.name(), HttpRequest.BodyPublishers.noBody());
                    } else if (body != null && !body.isBlank()) {
                        String resolvedBody = resolvePathParams(body, role.getParams());
                        reqBuilder.method(method.name(), HttpRequest.BodyPublishers.ofString(resolvedBody, StandardCharsets.UTF_8));
                    } else {
                        reqBuilder.method(method.name(), HttpRequest.BodyPublishers.noBody());
                    }

                    HttpResponse<byte[]> response = httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofByteArray());
                    actualStatus = response.statusCode();
                    resBody = response.body();
                    responseBytes = resBody != null ? resBody.length : 0;
                    String bodyString = resBody != null ? new String(resBody, StandardCharsets.UTF_8) : "";

                    // A. Evaluate HTTP Status Code
                    if (actualStatus == expectedStatus) {
                        verdict = Verdict.PASS;
                    } else if (expectedStatus >= 400 && actualStatus >= 200 && actualStatus < 300) {
                        verdict = Verdict.REGRESSION_UNAUTHORIZED_ACCESS;
                    } else {
                        verdict = Verdict.STATUS_MISMATCH;
                    }

                    // B. Evaluate Policy Assertions (if status passed or was expected)
                    if (endpoint.getAssertions() != null && endpoint.getAssertions().hasAssertions()) {
                        PolicyAssertion pa = endpoint.getAssertions();

                        // Negative assertions (Must NOT contain) -> Data Leakage Check
                        if (pa.getBodyMustNotContain() != null) {
                            for (String forbidden : pa.getBodyMustNotContain()) {
                                if (bodyString.contains(forbidden)) {
                                    verdict = Verdict.REGRESSION_DATA_LEAKAGE;
                                    assertionFailure = "Response body contains prohibited sensitive text: '" + forbidden + "'";
                                    break;
                                }
                            }
                        }

                        // Prohibited regex check
                        if (verdict != Verdict.REGRESSION_DATA_LEAKAGE && pa.getRegexMustNotMatch() != null && !pa.getRegexMustNotMatch().isBlank()) {
                            try {
                                if (Pattern.compile(pa.getRegexMustNotMatch()).matcher(bodyString).find()) {
                                    verdict = Verdict.REGRESSION_DATA_LEAKAGE;
                                    assertionFailure = "Response body matches prohibited pattern: " + pa.getRegexMustNotMatch();
                                }
                            } catch (Exception e) {
                                log.warn("Invalid regex pattern in policy assertion: {}", e.getMessage());
                            }
                        }

                        // Positive assertions (Must contain)
                        if (verdict == Verdict.PASS && pa.getBodyMustContain() != null) {
                            for (String required : pa.getBodyMustContain()) {
                                if (!bodyString.contains(required)) {
                                    verdict = Verdict.ASSERTION_FAILED;
                                    assertionFailure = "Response body missing required confirmation: '" + required + "'";
                                    break;
                                }
                            }
                        }

                        // Required regex pattern
                        if (verdict == Verdict.PASS && pa.getRegexPattern() != null && !pa.getRegexPattern().isBlank()) {
                            try {
                                if (!Pattern.compile(pa.getRegexPattern()).matcher(bodyString).find()) {
                                    verdict = Verdict.ASSERTION_FAILED;
                                    assertionFailure = "Response body does not match expected regex: " + pa.getRegexPattern();
                                }
                            } catch (Exception e) {
                                log.warn("Invalid regex pattern: {}", e.getMessage());
                            }
                        }

                        // JSONPath / Key equality assertions
                        if (verdict == Verdict.PASS && pa.getJsonPathEquals() != null && !pa.getJsonPathEquals().isEmpty()) {
                            try {
                                JsonNode rootNode = JsonUtils.getJsonMapper().readTree(bodyString);
                                for (Map.Entry<String, String> entry : pa.getJsonPathEquals().entrySet()) {
                                    String pathKey = entry.getKey();
                                    String expectedVal = entry.getValue();
                                    String actualVal = extractJsonValue(rootNode, pathKey);
                                    if (!Objects.equals(expectedVal, actualVal)) {
                                        verdict = Verdict.ASSERTION_FAILED;
                                        assertionFailure = "JSON field '" + pathKey + "' expected '" + expectedVal + "' but was '" + actualVal + "'";
                                        break;
                                    }
                                }
                            } catch (Exception ignored) {
                                verdict = Verdict.ASSERTION_FAILED;
                                assertionFailure = "Failed to parse response body as JSON for assertion checks";
                            }
                        }
                    }

                    // C. Automated BOLA / IDOR Cross-Tenant Parameter Mutation Check
                    if (verdict == Verdict.PASS && containsParamPlaceholder(cleanPath)) {
                        for (Role otherRole : roles) {
                            if (otherRole.getName().equals(role.getName())) continue;
                            if (otherRole.getParams() == null || otherRole.getParams().isEmpty()) continue;

                            String crossTenantPath = resolvePathParams(cleanPath, otherRole.getParams());
                            if (!crossTenantPath.equals(resolvedPath)) {
                                // Probe other tenant resource with current role credentials
                                boolean crossAccessAllowed = checkCrossTenantAccess(
                                        baseUrl + crossTenantPath,
                                        endpoint.getMethod(),
                                        requestHeaders,
                                        body,
                                        timeout
                                );

                                if (crossAccessAllowed) {
                                    verdict = Verdict.BOLA_IDOR_VULNERABILITY;
                                    bolaDetected = true;
                                    assertionFailure = "BOLA/IDOR detected: Role '" + role.getName() + "' successfully accessed resource belonging to '" + otherRole.getName() + "' at " + crossTenantPath;
                                    break;
                                }
                            }
                        }
                    }

                } catch (Exception e) {
                    actualStatus = 0;
                    verdict = Verdict.NETWORK_ERROR;
                    errorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                }

                long durationMs = (System.nanoTime() - startTime) / 1_000_000;

                // Generate actionable code remediation
                Map<String, String> remediation = RemediationAdvisor.generateRemediation(
                        verdict,
                        endpoint,
                        role.getName(),
                        expectedStatus,
                        actualStatus
                );

                results.add(new MatrixResult(
                        UUID.randomUUID().toString(),
                        runId,
                        endpoint.getId(),
                        endpoint.getName(),
                        endpoint.getMethod(),
                        endpoint.getPath(),
                        role.getName(),
                        expectedStatus,
                        actualStatus,
                        responseBytes,
                        durationMs,
                        verdict,
                        errorMessage,
                        assertionFailure,
                        bolaDetected,
                        remediation,
                        Instant.now().toString()
                ));
            }
        }

        databaseManager.insertMatrixResults(results);

        // 3. Dispatch webhook alerts if configured
        WebhookConfig webhookConfig = databaseManager.getWebhookConfig();
        if (webhookConfig.isEnabled()) {
            webhookDispatcher.dispatchAlertAsync(webhookConfig, runId, targetBaseUrl, results);
        }

        return new DatabaseManager.MatrixRunResult(runId, results);
    }

    private void refreshRoleTokenIfNecessary(Role role, String targetBaseUrl) {
        AuthHandler handler = role.getAuthHandler();
        if (handler == null || !handler.isEnabled()) return;
        if (handler.getLoginUrl() == null || handler.getLoginUrl().isBlank()) return;

        // Check if cached token is still fresh
        if (role.getHeaderValue() != null && !role.getHeaderValue().isBlank() && handler.getLastRefreshedAt() != null) {
            try {
                Instant refreshedInstant = Instant.parse(handler.getLastRefreshedAt());
                long ageSeconds = Duration.between(refreshedInstant, Instant.now()).toSeconds();
                if (ageSeconds < handler.getCacheTtlSeconds()) {
                    return; // Still fresh
                }
            } catch (Exception ignored) {}
        }

        String fullLoginUrl = handler.getLoginUrl().trim();
        if (fullLoginUrl.startsWith("/")) {
            fullLoginUrl = targetBaseUrl + fullLoginUrl;
        }

        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(fullLoginUrl))
                    .timeout(Duration.ofSeconds(10));

            if (handler.getLoginHeaders() != null) {
                for (Map.Entry<String, String> h : handler.getLoginHeaders().entrySet()) {
                    if (!isRestrictedHeader(h.getKey())) {
                        builder.header(h.getKey(), h.getValue());
                    }
                }
            }
            builder.header("Accept", "application/json");

            HttpMethod method = handler.getLoginMethod() != null ? handler.getLoginMethod() : HttpMethod.POST;
            String loginBody = handler.getLoginBody();
            if (loginBody != null && !loginBody.isBlank()) {
                builder.header("Content-Type", "application/json");
                builder.method(method.name(), HttpRequest.BodyPublishers.ofString(loginBody, StandardCharsets.UTF_8));
            } else {
                builder.method(method.name(), HttpRequest.BodyPublishers.noBody());
            }

            HttpResponse<String> loginRes = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (loginRes.statusCode() >= 200 && loginRes.statusCode() < 300) {
                String token = extractToken(loginRes.body(), handler.getTokenPath());
                if (token != null && !token.isBlank()) {
                    String prefix = handler.getTokenPrefix() != null ? handler.getTokenPrefix() : "";
                    String finalHeaderValue = prefix + token;
                    role.setHeaderValue(finalHeaderValue);
                    handler.setLastRefreshedAt(Instant.now().toString());

                    databaseManager.updateRoleHeader(role.getName(), finalHeaderValue, JsonUtils.toJson(handler));
                    log.info("Successfully refreshed auth token for role '{}'", role.getName());
                }
            } else {
                log.warn("AuthHandler login failed for role '{}': HTTP {}", role.getName(), loginRes.statusCode());
            }
        } catch (Exception e) {
            log.error("AuthHandler error for role '{}': {}", role.getName(), e.getMessage());
        }
    }

    private String extractToken(String responseBody, String tokenPath) {
        if (responseBody == null || responseBody.isBlank()) return null;
        try {
            JsonNode current = JsonUtils.getJsonMapper().readTree(responseBody);
            String path = (tokenPath != null && !tokenPath.isBlank()) ? tokenPath : "token";
            String[] segments = path.split("\\.");
            for (String seg : segments) {
                if (current.has(seg)) {
                    current = current.get(seg);
                } else {
                    return null;
                }
            }
            return current.isTextual() ? current.asText() : current.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean checkCrossTenantAccess(String targetUrl, HttpMethod method, Map<String, String> headers, String body, int timeout) {
        try {
            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .timeout(Duration.ofMillis(timeout));

            for (Map.Entry<String, String> entry : headers.entrySet()) {
                if (!isRestrictedHeader(entry.getKey())) {
                    reqBuilder.header(entry.getKey(), entry.getValue());
                }
            }

            if (method == HttpMethod.GET || method == HttpMethod.HEAD) {
                reqBuilder.method(method.name(), HttpRequest.BodyPublishers.noBody());
            } else if (body != null && !body.isBlank()) {
                reqBuilder.method(method.name(), HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            } else {
                reqBuilder.method(method.name(), HttpRequest.BodyPublishers.noBody());
            }

            HttpResponse<byte[]> res = httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofByteArray());
            // If the unauthorized cross-tenant request returns 2xx OK, BOLA is present!
            return res.statusCode() >= 200 && res.statusCode() < 300;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean containsParamPlaceholder(String path) {
        return path != null && PARAM_PATTERN.matcher(path).find();
    }

    private String resolvePathParams(String template, Map<String, String> params) {
        if (template == null) return "";
        if (params == null || params.isEmpty()) return template;

        Matcher matcher = PARAM_PATTERN.matcher(template);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String paramKey = matcher.group(1);
            String val = params.getOrDefault(paramKey, "101");
            matcher.appendReplacement(sb, Matcher.quoteReplacement(val));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private String extractJsonValue(JsonNode root, String pathKey) {
        if (root == null || pathKey == null) return null;
        String[] parts = pathKey.split("\\.");
        JsonNode curr = root;
        for (String p : parts) {
            if (curr.has(p)) curr = curr.get(p);
            else return null;
        }
        return curr.isTextual() ? curr.asText() : curr.asText();
    }

    private static final Set<String> RESTRICTED_HEADERS = Set.of(
            "host", "content-length", "connection", "upgrade", "transfer-encoding"
    );

    private boolean isRestrictedHeader(String name) {
        return name != null && RESTRICTED_HEADERS.contains(name.toLowerCase());
    }
}
