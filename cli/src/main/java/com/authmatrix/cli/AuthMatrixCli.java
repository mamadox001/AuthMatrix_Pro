package com.authmatrix.cli;

import com.authmatrix.shared.model.*;
import com.authmatrix.shared.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Command(
        name = "authmatrix",
        mixinStandardHelpOptions = true,
        version = "AuthMatrix Pro CLI 0.1.0",
        description = "Headless CI/CD CLI for declarative RBAC and authorization contract verification"
)
public class AuthMatrixCli implements Runnable {

    @Command(
            name = "verify",
            mixinStandardHelpOptions = true,
            description = "Verify RBAC contract defined in YAML file against target base URL"
    )
    public static class VerifyCommand implements Callable<Integer> {

        @Parameters(index = "0", description = "Path to .authmatrix.yaml specification file")
        private File yamlFile;

        @Option(names = {"-u", "--url"}, description = "Override target_base_url from the YAML file")
        private String urlOverride;

        @Option(names = {"-t", "--timeout"}, defaultValue = "10000", description = "Request timeout in milliseconds (default: 10000)")
        private int timeoutMs;

        @Option(names = {"--json"}, description = "Output raw JSON summary instead of an ASCII table")
        private boolean jsonOutput;

        @Option(names = {"--sarif-out"}, description = "Output SARIF v2.1.0 report file for GitHub Code Scanning")
        private File sarifOut;

        @Option(names = {"--html-out"}, description = "Output standalone executive HTML report file")
        private File htmlOut;

        @Option(names = {"--markdown-out"}, description = "Output markdown summary report file for CI PR comments")
        private File markdownOut;

        @Option(names = {"--strict"}, description = "Enforce strict zero-violation mode (fail if any assertion/mismatch occurs)")
        private boolean strict;

        private static final Pattern ENV_PATTERN = Pattern.compile("\\$\\{([A-Za-z0-9_]+)\\}");
        private static final Pattern PARAM_PATTERN = Pattern.compile("\\{([A-Za-z0-9_-]+)\\}");

        @Override
        public Integer call() {
            if (!yamlFile.exists()) {
                System.err.println("Error: File not found: " + yamlFile.getAbsolutePath());
                return 1;
            }

            String content;
            try {
                content = Files.readString(yamlFile.toPath(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                System.err.println("Error reading file: " + e.getMessage());
                return 1;
            }

            AuthMatrixYaml contract;
            try {
                contract = JsonUtils.fromYaml(content);
            } catch (Exception e) {
                System.err.println("Error parsing YAML contract: " + e.getMessage());
                return 1;
            }

            String targetBaseUrl = (urlOverride != null && !urlOverride.isBlank())
                    ? urlOverride
                    : contract.getTargetBaseUrl();

            if (targetBaseUrl == null || targetBaseUrl.isBlank()) {
                System.err.println("Error: No target_base_url specified in YAML or via --url option.");
                return 1;
            }

            targetBaseUrl = targetBaseUrl.trim();
            if (!targetBaseUrl.startsWith("http://") && !targetBaseUrl.startsWith("https://")) {
                System.err.println("Error: target_base_url must use http or https protocol.");
                return 1;
            }

            if (targetBaseUrl.endsWith("/")) {
                targetBaseUrl = targetBaseUrl.substring(0, targetBaseUrl.length() - 1);
            }

            // Interpolate environment variables in role headers
            Map<String, AuthMatrixYaml.YamlRole> roles = contract.getRoles();
            if (roles != null) {
                for (Map.Entry<String, AuthMatrixYaml.YamlRole> entry : roles.entrySet()) {
                    String val = entry.getValue().getHeaderValue();
                    if (val != null && val.contains("${")) {
                        Matcher matcher = ENV_PATTERN.matcher(val);
                        StringBuilder sb = new StringBuilder();
                        while (matcher.find()) {
                            String envVarName = matcher.group(1);
                            String envVal = System.getenv(envVarName);
                            if (envVal == null) {
                                System.err.printf("Warning: Environment variable '%s' referenced in role '%s' is unset.%n",
                                        envVarName, entry.getKey());
                                envVal = "";
                            }
                            matcher.appendReplacement(sb, Matcher.quoteReplacement(envVal));
                        }
                        matcher.appendTail(sb);
                        entry.getValue().setHeaderValue(sb.toString());
                    }
                }
            }

            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();

            // Auto-refresh dynamic auth tokens if configured
            if (roles != null) {
                for (Map.Entry<String, AuthMatrixYaml.YamlRole> roleEntry : roles.entrySet()) {
                    AuthMatrixYaml.YamlRole rConfig = roleEntry.getValue();
                    if (rConfig.getAuthHandler() != null && rConfig.getAuthHandler().isEnabled()) {
                        refreshRoleTokenIfNecessary(client, targetBaseUrl, roleEntry.getKey(), rConfig);
                    }
                }
            }

            String runId = UUID.randomUUID().toString();
            List<MatrixResult> matrixResults = new ArrayList<>();
            List<RowResult> displayResults = new ArrayList<>();
            boolean allPassed = true;

            List<AuthMatrixYaml.YamlEndpoint> endpoints = contract.getEndpoints() != null
                    ? contract.getEndpoints()
                    : Collections.emptyList();

            for (AuthMatrixYaml.YamlEndpoint ep : endpoints) {
                HttpMethod method = ep.getMethod() != null ? ep.getMethod() : HttpMethod.GET;
                String epPath = ep.getPath() != null ? ep.getPath() : "/";
                if (!epPath.startsWith("/")) epPath = "/" + epPath;

                String bodyStr = null;
                if (ep.getBody() != null) {
                    if (ep.getBody() instanceof String s) {
                        bodyStr = s;
                    } else {
                        bodyStr = JsonUtils.toJson(ep.getBody());
                    }
                }

                if (roles != null) {
                    for (Map.Entry<String, AuthMatrixYaml.YamlRole> roleEntry : roles.entrySet()) {
                        String roleName = roleEntry.getKey();
                        AuthMatrixYaml.YamlRole roleConfig = roleEntry.getValue();

                        int expectedStatus = 200;
                        if (ep.getExpect() != null && ep.getExpect().containsKey(roleName)) {
                            expectedStatus = ep.getExpect().get(roleName);
                        }

                        Map<String, String> reqHeaders = new HashMap<>();
                        if (ep.getHeaders() != null) {
                            reqHeaders.putAll(ep.getHeaders());
                        }
                        reqHeaders.put("Accept", "application/json");

                        if (bodyStr != null && !bodyStr.isBlank()) {
                            reqHeaders.putIfAbsent("Content-Type", "application/json");
                        }

                        String headerName = roleConfig.getHeaderName() != null ? roleConfig.getHeaderName() : "Authorization";
                        String headerVal = roleConfig.getHeaderValue();
                        if (headerVal != null && !headerVal.trim().isEmpty()) {
                            reqHeaders.put(headerName, headerVal);
                        } else {
                            reqHeaders.remove(headerName);
                        }

                        String resolvedPath = resolvePathParams(epPath, roleConfig.getParams());
                        String fullUrl = targetBaseUrl + resolvedPath;

                        long start = System.nanoTime();
                        int actualStatus = 0;
                        Verdict verdict = Verdict.PASS;
                        String errMsg = null;
                        String assertionFailure = null;
                        boolean bolaDetected = false;
                        long resBytesLen = 0;

                        try {
                            HttpRequest.Builder builder = HttpRequest.newBuilder()
                                    .uri(URI.create(fullUrl))
                                    .timeout(Duration.ofMillis(timeoutMs));

                            for (Map.Entry<String, String> h : reqHeaders.entrySet()) {
                                String hName = h.getKey();
                                if (isRestrictedHeader(hName)) continue;
                                try {
                                    builder.header(hName, h.getValue());
                                } catch (Exception ignored) {}
                            }

                            if (method == HttpMethod.GET || method == HttpMethod.HEAD) {
                                builder.method(method.name(), HttpRequest.BodyPublishers.noBody());
                            } else if (bodyStr != null && !bodyStr.isBlank()) {
                                String resolvedBody = resolvePathParams(bodyStr, roleConfig.getParams());
                                builder.method(method.name(), HttpRequest.BodyPublishers.ofString(resolvedBody, StandardCharsets.UTF_8));
                            } else {
                                builder.method(method.name(), HttpRequest.BodyPublishers.noBody());
                            }

                            HttpResponse<byte[]> res = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
                            actualStatus = res.statusCode();
                            byte[] resBytes = res.body();
                            resBytesLen = resBytes != null ? resBytes.length : 0;
                            String bodyString = resBytes != null ? new String(resBytes, StandardCharsets.UTF_8) : "";

                            // 1. Status evaluation
                            if (actualStatus == expectedStatus) {
                                verdict = Verdict.PASS;
                            } else if (expectedStatus >= 400 && actualStatus >= 200 && actualStatus < 300) {
                                verdict = Verdict.REGRESSION_UNAUTHORIZED_ACCESS;
                            } else {
                                verdict = Verdict.STATUS_MISMATCH;
                            }

                            // 2. Policy assertions evaluation
                            if (ep.getAssertions() != null && ep.getAssertions().hasAssertions()) {
                                PolicyAssertion pa = ep.getAssertions();
                                if (pa.getBodyMustNotContain() != null) {
                                    for (String f : pa.getBodyMustNotContain()) {
                                        if (bodyString.contains(f)) {
                                            verdict = Verdict.REGRESSION_DATA_LEAKAGE;
                                            assertionFailure = "Leaked text: '" + f + "'";
                                            break;
                                        }
                                    }
                                }
                                if (verdict == Verdict.PASS && pa.getBodyMustContain() != null) {
                                    for (String r : pa.getBodyMustContain()) {
                                        if (!bodyString.contains(r)) {
                                            verdict = Verdict.ASSERTION_FAILED;
                                            assertionFailure = "Missing required: '" + r + "'";
                                            break;
                                        }
                                    }
                                }
                            }

                            // 3. Cross-tenant BOLA evaluation
                            if (verdict == Verdict.PASS && containsParamPlaceholder(epPath)) {
                                for (Map.Entry<String, AuthMatrixYaml.YamlRole> otherRoleEntry : roles.entrySet()) {
                                    if (otherRoleEntry.getKey().equals(roleName)) continue;
                                    String crossTenantPath = resolvePathParams(epPath, otherRoleEntry.getValue().getParams());
                                    if (!crossTenantPath.equals(resolvedPath)) {
                                        if (checkCrossAccess(client, targetBaseUrl + crossTenantPath, method, reqHeaders, bodyStr, timeoutMs)) {
                                            verdict = Verdict.BOLA_IDOR_VULNERABILITY;
                                            bolaDetected = true;
                                            assertionFailure = "Cross-tenant access allowed to " + crossTenantPath;
                                            break;
                                        }
                                    }
                                }
                            }

                        } catch (Exception e) {
                            actualStatus = 0;
                            verdict = Verdict.NETWORK_ERROR;
                            errMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                        }

                        long durationMs = (System.nanoTime() - start) / 1_000_000;

                        if (verdict != Verdict.PASS) {
                            if (strict || verdict == Verdict.REGRESSION_UNAUTHORIZED_ACCESS || verdict == Verdict.BOLA_IDOR_VULNERABILITY || verdict == Verdict.REGRESSION_DATA_LEAKAGE) {
                                allPassed = false;
                            }
                        }

                        displayResults.add(new RowResult(
                                method.name(),
                                epPath,
                                roleName,
                                expectedStatus,
                                actualStatus,
                                durationMs,
                                verdict,
                                errMsg != null ? errMsg : assertionFailure
                        ));

                        matrixResults.add(new MatrixResult(
                                UUID.randomUUID().toString(),
                                runId,
                                UUID.randomUUID().toString(),
                                ep.getName(),
                                method,
                                epPath,
                                roleName,
                                expectedStatus,
                                actualStatus,
                                resBytesLen,
                                durationMs,
                                verdict,
                                errMsg,
                                assertionFailure,
                                bolaDetected,
                                Collections.emptyMap(),
                                Instant.now().toString()
                        ));
                    }
                }
            }

            // Report generation
            if (sarifOut != null) {
                try {
                    String sarif = SarifReportGenerator.generateSarif(runId, matrixResults, targetBaseUrl);
                    Files.writeString(sarifOut.toPath(), sarif, StandardCharsets.UTF_8);
                    System.out.println("SARIF v2.1.0 report written to: " + sarifOut.getAbsolutePath());
                } catch (Exception e) {
                    System.err.println("Failed to write SARIF report: " + e.getMessage());
                }
            }

            if (htmlOut != null) {
                try {
                    String html = HtmlReportGenerator.generateHtml(runId, matrixResults, targetBaseUrl);
                    Files.writeString(htmlOut.toPath(), html, StandardCharsets.UTF_8);
                    System.out.println("Executive HTML report written to: " + htmlOut.getAbsolutePath());
                } catch (Exception e) {
                    System.err.println("Failed to write HTML report: " + e.getMessage());
                }
            }

            if (markdownOut != null) {
                try {
                    String md = MarkdownReportGenerator.generateMarkdown(runId, matrixResults, targetBaseUrl);
                    Files.writeString(markdownOut.toPath(), md, StandardCharsets.UTF_8);
                    System.out.println("Markdown report written to: " + markdownOut.getAbsolutePath());
                } catch (Exception e) {
                    System.err.println("Failed to write Markdown report: " + e.getMessage());
                }
            }

            if (jsonOutput) {
                System.out.println(JsonUtils.toPrettyJson(Map.of(
                        "target_base_url", targetBaseUrl,
                        "run_id", runId,
                        "total", displayResults.size(),
                        "passed", allPassed,
                        "results", displayResults
                )));
            } else {
                renderAsciiTable(targetBaseUrl, displayResults);
            }

            return allPassed ? 0 : 1;
        }

        private static void refreshRoleTokenIfNecessary(HttpClient client, String baseUrl, String roleName, AuthMatrixYaml.YamlRole role) {
            AuthHandler handler = role.getAuthHandler();
            if (handler == null || handler.getLoginUrl() == null || handler.getLoginUrl().isBlank()) return;

            String loginUrl = handler.getLoginUrl().trim();
            if (loginUrl.startsWith("/")) loginUrl = baseUrl + loginUrl;

            try {
                HttpRequest.Builder b = HttpRequest.newBuilder().uri(URI.create(loginUrl)).timeout(Duration.ofSeconds(10));
                if (handler.getLoginHeaders() != null) {
                    for (Map.Entry<String, String> h : handler.getLoginHeaders().entrySet()) {
                        if (!isRestrictedHeader(h.getKey())) b.header(h.getKey(), h.getValue());
                    }
                }
                b.header("Accept", "application/json");

                HttpMethod method = handler.getLoginMethod() != null ? handler.getLoginMethod() : HttpMethod.POST;
                if (handler.getLoginBody() != null && !handler.getLoginBody().isBlank()) {
                    b.header("Content-Type", "application/json");
                    b.method(method.name(), HttpRequest.BodyPublishers.ofString(handler.getLoginBody(), StandardCharsets.UTF_8));
                } else {
                    b.method(method.name(), HttpRequest.BodyPublishers.noBody());
                }

                HttpResponse<String> res = client.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (res.statusCode() >= 200 && res.statusCode() < 300) {
                    JsonNode node = JsonUtils.getJsonMapper().readTree(res.body());
                    String tokenPath = handler.getTokenPath() != null ? handler.getTokenPath() : "token";
                    String[] segs = tokenPath.split("\\.");
                    for (String s : segs) {
                        if (node.has(s)) node = node.get(s);
                    }
                    String tokenVal = node.isTextual() ? node.asText() : node.toString();
                    String prefix = handler.getTokenPrefix() != null ? handler.getTokenPrefix() : "";
                    role.setHeaderValue(prefix + tokenVal);
                }
            } catch (Exception ignored) {}
        }

        private static boolean checkCrossAccess(HttpClient client, String targetUrl, HttpMethod method, Map<String, String> headers, String body, int timeout) {
            try {
                HttpRequest.Builder b = HttpRequest.newBuilder().uri(URI.create(targetUrl)).timeout(Duration.ofMillis(timeout));
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    if (!isRestrictedHeader(entry.getKey())) b.header(entry.getKey(), entry.getValue());
                }
                if (method == HttpMethod.GET || method == HttpMethod.HEAD) {
                    b.method(method.name(), HttpRequest.BodyPublishers.noBody());
                } else if (body != null && !body.isBlank()) {
                    b.method(method.name(), HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
                } else {
                    b.method(method.name(), HttpRequest.BodyPublishers.noBody());
                }
                HttpResponse<byte[]> res = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
                return res.statusCode() >= 200 && res.statusCode() < 300;
            } catch (Exception e) {
                return false;
            }
        }

        private static boolean containsParamPlaceholder(String path) {
            return path != null && PARAM_PATTERN.matcher(path).find();
        }

        private static String resolvePathParams(String template, Map<String, String> params) {
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

        private static final Set<String> RESTRICTED_HEADERS = Set.of(
                "host", "content-length", "connection", "upgrade", "transfer-encoding"
        );

        private static boolean isRestrictedHeader(String name) {
            return name != null && RESTRICTED_HEADERS.contains(name.toLowerCase());
        }

        private void renderAsciiTable(String baseUrl, List<RowResult> results) {
            System.out.println();
            System.out.println("==========================================================================");
            System.out.println(" AuthMatrix Pro - Declarative RBAC & Authorization Contract Verification");
            System.out.println(" Target: " + baseUrl);
            System.out.println("==========================================================================");
            System.out.println();

            int methodW = 6;
            int pathW = 4;
            int roleW = 4;
            int expW = 8;
            int actW = 6;
            int timeW = 6;
            int verdictW = 7;

            for (RowResult r : results) {
                if (r.method().length() > methodW) methodW = r.method().length();
                if (r.path().length() > pathW) pathW = r.path().length();
                if (r.role().length() > roleW) roleW = r.role().length();
                if (r.verdict().name().length() > verdictW) verdictW = r.verdict().name().length();
            }

            String format = String.format("%%-%ds | %%-%ds | %%-%ds | %%-%ds | %%-%ds | %%-%ds | %%-%ds%%n",
                    methodW, pathW, roleW, expW, actW, timeW, verdictW);

            String separator = String.format("%s-+-%s-+-%s-+-%s-+-%s-+-%s-+-%s",
                    "-".repeat(methodW),
                    "-".repeat(pathW),
                    "-".repeat(roleW),
                    "-".repeat(expW),
                    "-".repeat(actW),
                    "-".repeat(timeW),
                    "-".repeat(verdictW));

            System.out.printf(format, "METHOD", "PATH", "ROLE", "EXPECTED", "ACTUAL", "TIME", "VERDICT");
            System.out.println(separator);

            int passCount = 0;
            int regCount = 0;
            int bolaCount = 0;
            int leakCount = 0;
            int assertCount = 0;
            int mismatchCount = 0;
            int netErrCount = 0;

            for (RowResult r : results) {
                String timeStr = r.durationMs() + "ms";
                System.out.printf(format,
                        r.method(),
                        r.path(),
                        r.role(),
                        String.valueOf(r.expectedStatus()),
                        String.valueOf(r.actualStatus()),
                        timeStr,
                        r.verdict().name()
                );

                switch (r.verdict()) {
                    case PASS -> passCount++;
                    case REGRESSION_UNAUTHORIZED_ACCESS -> regCount++;
                    case BOLA_IDOR_VULNERABILITY -> bolaCount++;
                    case REGRESSION_DATA_LEAKAGE -> leakCount++;
                    case ASSERTION_FAILED -> assertCount++;
                    case STATUS_MISMATCH -> mismatchCount++;
                    case NETWORK_ERROR -> netErrCount++;
                }
            }

            System.out.println(separator);
            System.out.printf("Summary: %d Passed, %d BOLA, %d Regressions, %d Leaks, %d Assertions, %d Mismatches (Total: %d)%n",
                    passCount, bolaCount, regCount, leakCount, assertCount, mismatchCount, results.size());
            System.out.println();
        }
    }

    public record RowResult(
            String method,
            String path,
            String role,
            int expectedStatus,
            int actualStatus,
            long durationMs,
            Verdict verdict,
            String errorMessage
    ) {}

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new AuthMatrixCli());
        cmd.addSubcommand("verify", new VerifyCommand());
        int exitCode = cmd.execute(args);
        System.exit(exitCode);
    }
}
