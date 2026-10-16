package com.authmatrix.shared.util;

import com.authmatrix.shared.model.MatrixResult;
import com.authmatrix.shared.model.Verdict;

import java.time.Instant;
import java.util.List;

public class MarkdownReportGenerator {

    public static String generateMarkdown(String runId, List<MatrixResult> results, String targetBaseUrl) {
        StringBuilder sb = new StringBuilder();

        int total = results != null ? results.size() : 0;
        int passed = 0;
        int regressions = 0;
        int bola = 0;
        int dataLeaks = 0;
        int assertionFailures = 0;
        int mismatches = 0;
        int errors = 0;

        if (results != null) {
            for (MatrixResult r : results) {
                switch (r.getVerdict()) {
                    case PASS -> passed++;
                    case REGRESSION_UNAUTHORIZED_ACCESS -> regressions++;
                    case BOLA_IDOR_VULNERABILITY -> bola++;
                    case REGRESSION_DATA_LEAKAGE -> dataLeaks++;
                    case ASSERTION_FAILED -> assertionFailures++;
                    case STATUS_MISMATCH -> mismatches++;
                    case NETWORK_ERROR -> errors++;
                }
            }
        }

        boolean secure = (regressions == 0 && bola == 0 && dataLeaks == 0 && assertionFailures == 0);

        sb.append("# 🛡️ AuthMatrix Pro — Security Verification Report\n\n");
        sb.append("**Target Host:** `").append(targetBaseUrl != null ? targetBaseUrl : "N/A").append("`  \n");
        sb.append("**Execution Run ID:** `").append(runId != null ? runId : "N/A").append("`  \n");
        sb.append("**Timestamp:** ").append(Instant.now().toString()).append("  \n");
        sb.append("**Status:** ").append(secure ? "✅ **ALL POLICIES SATISFIED (PASSED)**" : "🚨 **AUTHORIZATION VIOLATIONS DETECTED**").append("\n\n");

        sb.append("## 📊 Executive Summary\n\n");
        sb.append("| Metric | Count | Status |\n");
        sb.append("| :--- | :--- | :--- |\n");
        sb.append("| **Total Evaluations** | ").append(total).append(" | - |\n");
        sb.append("| **Passed** | ").append(passed).append(" | ✅ |\n");
        sb.append("| **BOLA / IDOR Violations** | ").append(bola).append(" | ").append(bola > 0 ? "🚨 Critical" : "✅ 0").append(" |\n");
        sb.append("| **Unauthorized Regressions** | ").append(regressions).append(" | ").append(regressions > 0 ? "❌ High" : "✅ 0").append(" |\n");
        sb.append("| **Data Leakage Failures** | ").append(dataLeaks).append(" | ").append(dataLeaks > 0 ? "⚠️ High" : "✅ 0").append(" |\n");
        sb.append("| **Assertion Violations** | ").append(assertionFailures).append(" | ").append(assertionFailures > 0 ? "⚠️ Medium" : "✅ 0").append(" |\n");
        sb.append("| **Status Mismatches** | ").append(mismatches).append(" | ").append(mismatches > 0 ? "ℹ️ Note" : "✅ 0").append(" |\n");
        sb.append("| **Network Errors** | ").append(errors).append(" | ").append(errors > 0 ? "❌ Error" : "✅ 0").append(" |\n\n");

        if (!secure && results != null) {
            sb.append("## 🚨 Security Findings & Violations\n\n");
            sb.append("| Method | Path | Role | Expected | Actual | Verdict | Details |\n");
            sb.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

            for (MatrixResult r : results) {
                if (r.getVerdict() == Verdict.PASS) continue;

                String badge = switch (r.getVerdict()) {
                    case BOLA_IDOR_VULNERABILITY -> "🚨 **BOLA/IDOR**";
                    case REGRESSION_UNAUTHORIZED_ACCESS -> "❌ **REGRESSION**";
                    case REGRESSION_DATA_LEAKAGE -> "⚠️ **DATA LEAK**";
                    case ASSERTION_FAILED -> "⚠️ **ASSERTION**";
                    case STATUS_MISMATCH -> "ℹ️ MISMATCH";
                    case NETWORK_ERROR -> "🔌 NET ERROR";
                    default -> "✅ PASS";
                };

                String details = "";
                if (r.getAssertionFailure() != null) details = r.getAssertionFailure();
                else if (r.getErrorMessage() != null) details = r.getErrorMessage();
                else details = "Returned " + r.getActualStatus() + " instead of " + r.getExpectedStatus();

                sb.append("| `").append(r.getEndpointMethod()).append("` ")
                  .append("| `").append(r.getEndpointPath()).append("` ")
                  .append("| `").append(r.getRoleName()).append("` ")
                  .append("| ").append(r.getExpectedStatus()).append(" ")
                  .append("| ").append(r.getActualStatus()).append(" ")
                  .append("| ").append(badge).append(" ")
                  .append("| ").append(details.replace("|", "\\|")).append(" |\n");
            }
            sb.append("\n");
        }

        sb.append("## 📋 Matrix Results Breakdown\n\n");
        sb.append("| Method | Path | Role | Expected | Actual | Latency | Verdict |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");
        if (results != null) {
            for (MatrixResult r : results) {
                sb.append("| `").append(r.getEndpointMethod()).append("` ")
                  .append("| `").append(r.getEndpointPath()).append("` ")
                  .append("| `").append(r.getRoleName()).append("` ")
                  .append("| ").append(r.getExpectedStatus()).append(" ")
                  .append("| ").append(r.getActualStatus()).append(" ")
                  .append("| ").append(r.getDurationMs()).append("ms ")
                  .append("| ").append(r.getVerdict() == Verdict.PASS ? "✅ PASS" : r.getVerdict().name()).append(" |\n");
            }
        }
        sb.append("\n---\n*Generated automatically by AuthMatrix Pro CI Runner*\n");

        return sb.toString();
    }
}
