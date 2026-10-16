package com.authmatrix.shared.util;

import com.authmatrix.shared.model.MatrixResult;
import com.authmatrix.shared.model.Verdict;

import java.util.*;

public class SarifReportGenerator {

    public static String generateSarif(String runId, List<MatrixResult> results, String targetBaseUrl) {
        Map<String, Object> sarif = new LinkedHashMap<>();
        sarif.put("$schema", "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
        sarif.put("version", "2.1.0");

        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", "AuthMatrix Pro");
        driver.put("version", "0.1.0");
        driver.put("informationUri", "https://github.com/mamadox001/AuthMatrix_Pro");

        List<Map<String, Object>> rules = new ArrayList<>();
        rules.add(createRule("AUTH001", "Broken Object Level Authorization (BOLA/IDOR)",
                "Cross-tenant object access without authorization check", "error", "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"));
        rules.add(createRule("AUTH002", "Broken Function Level Authorization (BFLA)",
                "Unauthorized role granted access to restricted API endpoint", "error", "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"));
        rules.add(createRule("AUTH003", "Sensitive Data Leakage / Property Authorization Violation",
                "Response payload contains forbidden data or violated negative assertions", "error", "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"));
        rules.add(createRule("AUTH004", "Semantic Contract Assertion Violation",
                "API response body or structure did not satisfy required authorization assertions", "warning", "https://cwe.mitre.org/data/definitions/285.html"));
        rules.add(createRule("AUTH005", "HTTP Status Code Contract Mismatch",
                "Actual HTTP response status code differed from expected contract status", "note", "https://cwe.mitre.org/data/definitions/285.html"));

        driver.put("rules", rules);

        Map<String, Object> tool = Map.of("driver", driver);

        List<Map<String, Object>> sarifResults = new ArrayList<>();

        if (results != null) {
            for (MatrixResult r : results) {
                if (r.getVerdict() == Verdict.PASS) continue;

                String ruleId;
                String level;
                String title;

                switch (r.getVerdict()) {
                    case BOLA_IDOR_VULNERABILITY -> {
                        ruleId = "AUTH001";
                        level = "error";
                        title = "BOLA / IDOR Violation: Role '" + r.getRoleName() + "' accessed cross-tenant resource at " + r.getEndpointMethod() + " " + r.getEndpointPath();
                    }
                    case REGRESSION_UNAUTHORIZED_ACCESS -> {
                        ruleId = "AUTH002";
                        level = "error";
                        title = "Unauthorized Access Regression: Role '" + r.getRoleName() + "' received HTTP " + r.getActualStatus() + " (expected " + r.getExpectedStatus() + ") on " + r.getEndpointMethod() + " " + r.getEndpointPath();
                    }
                    case REGRESSION_DATA_LEAKAGE -> {
                        ruleId = "AUTH003";
                        level = "error";
                        title = "Sensitive Data Leakage: Response on " + r.getEndpointMethod() + " " + r.getEndpointPath() + " for role '" + r.getRoleName() + "' contains prohibited data";
                    }
                    case ASSERTION_FAILED -> {
                        ruleId = "AUTH004";
                        level = "warning";
                        title = "Assertion Failed on " + r.getEndpointMethod() + " " + r.getEndpointPath() + " for role '" + r.getRoleName() + "': " + (r.getAssertionFailure() != null ? r.getAssertionFailure() : "Policy assertion unsatisfied");
                    }
                    default -> {
                        ruleId = "AUTH005";
                        level = "note";
                        title = "Status Mismatch on " + r.getEndpointMethod() + " " + r.getEndpointPath() + " for role '" + r.getRoleName() + "': got " + r.getActualStatus() + ", expected " + r.getExpectedStatus();
                    }
                }

                Map<String, Object> sarifFinding = new LinkedHashMap<>();
                sarifFinding.put("ruleId", ruleId);
                sarifFinding.put("level", level);
                sarifFinding.put("message", Map.of("text", title));

                String cleanPath = r.getEndpointPath() != null ? r.getEndpointPath() : "/";
                Map<String, Object> location = Map.of(
                        "physicalLocation", Map.of(
                                "artifactLocation", Map.of("uri", cleanPath.startsWith("/") ? cleanPath.substring(1) : cleanPath),
                                "region", Map.of("startLine", 1)
                        )
                );
                sarifFinding.put("locations", List.of(location));

                Map<String, Object> props = new LinkedHashMap<>();
                props.put("endpointName", r.getEndpointName());
                props.put("method", r.getEndpointMethod() != null ? r.getEndpointMethod().name() : "GET");
                props.put("path", r.getEndpointPath());
                props.put("role", r.getRoleName());
                props.put("expectedStatus", r.getExpectedStatus());
                props.put("actualStatus", r.getActualStatus());
                props.put("verdict", r.getVerdict().name());
                if (r.getErrorMessage() != null) props.put("error", r.getErrorMessage());
                if (r.getAssertionFailure() != null) props.put("assertionDetails", r.getAssertionFailure());
                sarifFinding.put("properties", props);

                sarifResults.add(sarifFinding);
            }
        }

        Map<String, Object> run = new LinkedHashMap<>();
        run.put("tool", tool);
        run.put("results", sarifResults);
        if (runId != null) {
            run.put("automationLogicalId", Map.of("id", runId));
        }

        sarif.put("runs", List.of(run));
        return JsonUtils.toPrettyJson(sarif);
    }

    private static Map<String, Object> createRule(String id, String name, String shortDesc, String defaultLevel, String helpUri) {
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("id", id);
        rule.put("name", name);
        rule.put("shortDescription", Map.of("text", shortDesc));
        rule.put("defaultConfiguration", Map.of("level", defaultLevel));
        rule.put("helpUri", helpUri);
        return rule;
    }
}
