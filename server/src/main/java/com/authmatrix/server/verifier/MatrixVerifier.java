package com.authmatrix.server.verifier;

import com.authmatrix.server.db.DatabaseManager;
import com.authmatrix.shared.model.*;
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

@Service
public class MatrixVerifier {

    private static final Logger log = LoggerFactory.getLogger(MatrixVerifier.class);

    private final DatabaseManager databaseManager;
    private final HttpClient httpClient;

    public MatrixVerifier(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
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

        for (EndpointPolicy endpoint : endpoints) {
            for (Role role : roles) {
                int expectedStatus = endpoint.getExpect().getOrDefault(role.getName(), 200);

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

                String cleanPath = endpoint.getPath().startsWith("/") ? endpoint.getPath() : "/" + endpoint.getPath();
                String targetUrl = baseUrl + cleanPath;

                long startTime = System.nanoTime();
                int actualStatus = 0;
                long responseBytes = 0;
                Verdict verdict;
                String errorMessage = null;

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
                        reqBuilder.method(method.name(), HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
                    } else {
                        reqBuilder.method(method.name(), HttpRequest.BodyPublishers.noBody());
                    }

                    HttpResponse<byte[]> response = httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofByteArray());
                    actualStatus = response.statusCode();
                    byte[] resBody = response.body();
                    responseBytes = resBody != null ? resBody.length : 0;

                    if (actualStatus == expectedStatus) {
                        verdict = Verdict.PASS;
                    } else if (expectedStatus >= 400 && actualStatus >= 200 && actualStatus < 300) {
                        verdict = Verdict.REGRESSION_UNAUTHORIZED_ACCESS;
                    } else {
                        verdict = Verdict.STATUS_MISMATCH;
                    }

                } catch (Exception e) {
                    actualStatus = 0;
                    verdict = Verdict.NETWORK_ERROR;
                    errorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                }

                long durationMs = (System.nanoTime() - startTime) / 1_000_000;

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
                        Instant.now().toString()
                ));
            }
        }

        databaseManager.insertMatrixResults(results);
        return new DatabaseManager.MatrixRunResult(runId, results);
    }

    private static final Set<String> RESTRICTED_HEADERS = Set.of(
            "host", "content-length", "connection", "upgrade", "transfer-encoding"
    );

    private boolean isRestrictedHeader(String name) {
        return name != null && RESTRICTED_HEADERS.contains(name.toLowerCase());
    }
}
