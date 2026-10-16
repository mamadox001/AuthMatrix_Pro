package com.authmatrix.cli;

import com.authmatrix.shared.model.*;
import com.authmatrix.shared.util.JsonUtils;
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
import java.util.*;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Command(
        name = "authmatrix",
        mixinStandardHelpOptions = true,
        version = "AuthMatrix CLI 0.1.0",
        description = "Headless CI/CD CLI for declarative RBAC contract verification"
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

        private static final Pattern ENV_PATTERN = Pattern.compile("\\$\\{([A-Za-z0-9_]+)\\}");

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

            List<RowResult> results = new ArrayList<>();
            boolean allPassed = true;

            List<AuthMatrixYaml.YamlEndpoint> endpoints = contract.getEndpoints() != null
                    ? contract.getEndpoints()
                    : Collections.emptyList();

            for (AuthMatrixYaml.YamlEndpoint ep : endpoints) {
                HttpMethod method = ep.getMethod() != null ? ep.getMethod() : HttpMethod.GET;
                String epPath = ep.getPath() != null ? ep.getPath() : "/";
                if (!epPath.startsWith("/")) epPath = "/" + epPath;
                String fullUrl = targetBaseUrl + epPath;

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

                        long start = System.nanoTime();
                        int actualStatus = 0;
                        Verdict verdict;
                        String errMsg = null;

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
                                builder.method(method.name(), HttpRequest.BodyPublishers.ofString(bodyStr, StandardCharsets.UTF_8));
                            } else {
                                builder.method(method.name(), HttpRequest.BodyPublishers.noBody());
                            }

                            HttpResponse<byte[]> res = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
                            actualStatus = res.statusCode();

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
                            errMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                        }

                        long durationMs = (System.nanoTime() - start) / 1_000_000;

                        if (verdict != Verdict.PASS) {
                            allPassed = false;
                        }

                        results.add(new RowResult(
                                method.name(),
                                epPath,
                                roleName,
                                expectedStatus,
                                actualStatus,
                                durationMs,
                                verdict,
                                errMsg
                        ));
                    }
                }
            }

            if (jsonOutput) {
                System.out.println(JsonUtils.toPrettyJson(Map.of(
                        "target_base_url", targetBaseUrl,
                        "total", results.size(),
                        "passed", allPassed,
                        "results", results
                )));
            } else {
                renderAsciiTable(targetBaseUrl, results);
            }

            return allPassed ? 0 : 1;
        }

        private static final Set<String> RESTRICTED_HEADERS = Set.of(
                "host", "content-length", "connection", "upgrade", "transfer-encoding"
        );

        private static boolean isRestrictedHeader(String name) {
            return name != null && RESTRICTED_HEADERS.contains(name.toLowerCase());
        }

        private void renderAsciiTable(String baseUrl, List<RowResult> results) {
            System.out.println();
            System.out.println("AuthMatrix RBAC Contract Verification");
            System.out.println("Target: " + baseUrl);
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
                    case STATUS_MISMATCH -> mismatchCount++;
                    case NETWORK_ERROR -> netErrCount++;
                }
            }

            System.out.println(separator);
            System.out.printf("Summary: %d Passed, %d Regressions, %d Status Mismatches, %d Network Errors (Total: %d)%n",
                    passCount, regCount, mismatchCount, netErrCount, results.size());
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
