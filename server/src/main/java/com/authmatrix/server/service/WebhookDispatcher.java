package com.authmatrix.server.service;

import com.authmatrix.server.db.DatabaseManager;
import com.authmatrix.shared.model.MatrixResult;
import com.authmatrix.shared.model.Verdict;
import com.authmatrix.shared.model.WebhookConfig;
import com.authmatrix.shared.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

@Service
public class WebhookDispatcher {

    private static final Logger log = LoggerFactory.getLogger(WebhookDispatcher.class);

    private final HttpClient httpClient;

    public WebhookDispatcher() {
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public void dispatchAlertAsync(WebhookConfig config, String runId, String targetUrl, List<MatrixResult> results) {
        if (config == null || !config.isEnabled() || config.getWebhookUrl() == null || config.getWebhookUrl().isBlank()) {
            return;
        }

        Thread.ofVirtual().start(() -> {
            try {
                dispatchAlert(config, runId, targetUrl, results);
            } catch (Exception e) {
                log.error("Failed to dispatch webhook alert: {}", e.getMessage());
            }
        });
    }

    public boolean dispatchAlert(WebhookConfig config, String runId, String targetUrl, List<MatrixResult> results) {
        if (config == null || config.getWebhookUrl() == null || config.getWebhookUrl().isBlank()) {
            return false;
        }

        int regressions = 0;
        int bola = 0;
        int dataLeaks = 0;
        int failures = 0;

        if (results != null) {
            for (MatrixResult r : results) {
                if (r.getVerdict() == Verdict.REGRESSION_UNAUTHORIZED_ACCESS) regressions++;
                else if (r.getVerdict() == Verdict.BOLA_IDOR_VULNERABILITY) bola++;
                else if (r.getVerdict() == Verdict.REGRESSION_DATA_LEAKAGE) dataLeaks++;
                else if (r.getVerdict() != Verdict.PASS) failures++;
            }
        }

        String notifyOn = config.getNotifyOn() != null ? config.getNotifyOn().toLowerCase() : "all";
        if ("regression_only".equals(notifyOn) && (regressions + bola + dataLeaks) == 0) {
            return true;
        }
        if ("bola_only".equals(notifyOn) && bola == 0) {
            return true;
        }

        String platform = config.getPlatform() != null ? config.getPlatform().toLowerCase() : "generic";
        String payloadJson;

        if ("slack".equals(platform)) {
            payloadJson = buildSlackPayload(runId, targetUrl, regressions, bola, dataLeaks, failures);
        } else if ("discord".equals(platform)) {
            payloadJson = buildDiscordPayload(runId, targetUrl, regressions, bola, dataLeaks, failures);
        } else {
            payloadJson = buildGenericPayload(runId, targetUrl, regressions, bola, dataLeaks, failures, results);
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.getWebhookUrl().trim()))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(15))
                    .POST(HttpRequest.BodyPublishers.ofString(payloadJson, StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            log.info("Webhook alert sent to {}. Status: {}", config.getWebhookUrl(), response.statusCode());
            return response.statusCode() >= 200 && response.statusCode() < 300;
        } catch (Exception e) {
            log.error("Error sending webhook notification: {}", e.getMessage());
            return false;
        }
    }

    private String buildSlackPayload(String runId, String targetUrl, int reg, int bola, int leaks, int failures) {
        String title = (reg + bola + leaks) > 0
                ? "🚨 *AuthMatrix Pro Alert: Authorization Violations Detected*"
                : "✅ *AuthMatrix Pro: All Authorization Policies Passed*";

        String text = String.format("%s\n*Target:* `%s`\n*Run ID:* `%s`\n*BOLA/IDOR:* %d | *Regressions:* %d | *Data Leaks:* %d | *Other Failures:* %d",
                title, targetUrl, runId, bola, reg, leaks, failures);

        return JsonUtils.toJson(Map.of("text", text));
    }

    private String buildDiscordPayload(String runId, String targetUrl, int reg, int bola, int leaks, int failures) {
        boolean hasVuln = (reg + bola + leaks) > 0;
        int color = hasVuln ? 0xEF4444 : 0x10B981; // Red or Emerald

        Map<String, Object> embed = new LinkedHashMap<>();
        embed.put("title", hasVuln ? "🚨 AuthMatrix Pro Security Alert" : "✅ AuthMatrix Pro Verification Passed");
        embed.put("description", "Authorization verification results for `" + targetUrl + "`");
        embed.put("color", color);
        embed.put("fields", List.of(
                Map.of("name", "BOLA / IDOR Violations", "value", String.valueOf(bola), "inline", true),
                Map.of("name", "Unauthorized Access", "value", String.valueOf(reg), "inline", true),
                Map.of("name", "Data Leaks", "value", String.valueOf(leaks), "inline", true),
                Map.of("name", "Run ID", "value", "`" + runId + "`", "inline", false)
        ));

        return JsonUtils.toJson(Map.of("embeds", List.of(embed)));
    }

    private String buildGenericPayload(String runId, String targetUrl, int reg, int bola, int leaks, int failures, List<MatrixResult> results) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("event", "matrix.verification.completed");
        map.put("targetUrl", targetUrl);
        map.put("runId", runId);
        map.put("hasViolations", (reg + bola + leaks) > 0);
        map.put("summary", Map.of(
                "regressions", reg,
                "bola", bola,
                "dataLeaks", leaks,
                "otherFailures", failures,
                "totalTests", results != null ? results.size() : 0
        ));
        return JsonUtils.toJson(map);
    }
}
