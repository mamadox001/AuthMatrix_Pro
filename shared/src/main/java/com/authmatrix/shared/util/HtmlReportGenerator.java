package com.authmatrix.shared.util;

import com.authmatrix.shared.model.MatrixResult;
import com.authmatrix.shared.model.Verdict;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class HtmlReportGenerator {

    public static String generateHtml(String runId, List<MatrixResult> results, String targetBaseUrl) {
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

        int failed = total - passed;
        double passPct = total > 0 ? (passed * 100.0 / total) : 100.0;
        boolean isCompliant = (regressions == 0 && bola == 0 && dataLeaks == 0 && assertionFailures == 0);

        StringBuilder sb = new StringBuilder();
        sb.append("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AuthMatrix Pro - Executive Security & Authorization Audit Report</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #151d30;
      --border: #23314f;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --info: #818cf8;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding: 40px 24px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 32px;
    }
    .brand { display: flex; align-items: center; gap: 14px; }
    .brand-logo {
      width: 44px; height: 44px; background: linear-gradient(135deg, #0ea5e9, #6366f1);
      border-radius: 10px; display: flex; align-items: center; justify-content: center;
      font-size: 22px; font-weight: 800; color: #fff;
    }
    .brand-title { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
    .badge-status {
      display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px;
      border-radius: 20px; font-size: 13px; font-weight: 600;
    }
    .badge-pass { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-fail { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
    
    .meta-bar {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px;
      background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px;
      padding: 16px 20px; margin-bottom: 32px;
    }
    .meta-item { display: flex; flex-direction: column; gap: 4px; }
    .meta-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.5px; }
    .meta-val { font-size: 14px; font-weight: 600; font-family: var(--font-mono); color: var(--text); word-break: break-all; }

    .kpi-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px;
    }
    .kpi-card {
      background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 20px;
      display: flex; flex-direction: column; justify-content: space-between;
    }
    .kpi-num { font-size: 32px; font-weight: 800; line-height: 1.1; margin-top: 8px; }
    .c-pass { color: var(--success); }
    .c-danger { color: var(--danger); }
    .c-warn { color: var(--warning); }
    .c-primary { color: var(--primary); }

    .section-title { font-size: 18px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }

    .card {
      background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px;
      margin-bottom: 32px; overflow: hidden;
    }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
    th {
      background: rgba(15, 23, 42, 0.6); padding: 12px 16px; font-weight: 600;
      color: var(--text-muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border);
    }
    td { padding: 14px 16px; border-bottom: 1px solid rgba(35, 49, 79, 0.6); }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }
    .code-cell { font-family: var(--font-mono); font-size: 12px; }
    
    .pill {
      display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 600;
    }
    .pill-pass { background: rgba(16, 185, 129, 0.15); color: #34d399; }
    .pill-danger { background: rgba(239, 68, 68, 0.15); color: #f87171; }
    .pill-warn { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
    .pill-info { background: rgba(99, 102, 241, 0.15); color: #818cf8; }

    .finding-card {
      background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.25);
      border-radius: 10px; padding: 16px 20px; margin-bottom: 16px;
    }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .finding-title { font-weight: 700; font-size: 15px; color: #fca5a5; }
    .finding-desc { font-size: 13px; color: var(--text-muted); margin-bottom: 12px; }
    .code-box {
      background: #080c14; border: 1px solid #1e293b; border-radius: 8px;
      padding: 12px; font-family: var(--font-mono); font-size: 12px; color: #cbd5e1;
      overflow-x: auto; white-space: pre-wrap; margin-top: 8px;
    }
    .remed-tag {
      font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--primary); margin-top: 10px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">
        <div class="brand-logo">A</div>
        <div>
          <div class="brand-title">AuthMatrix Pro</div>
          <div style="font-size: 12px; color: var(--text-muted);">Declarative RBAC Contract & Authorization Audit</div>
        </div>
      </div>
      <div>
""");

        if (isCompliant) {
            sb.append("<div class=\"badge-status badge-pass\">🛡️ 100% AUTHORIZATION COMPLIANT</div>");
        } else {
            sb.append("<div class=\"badge-status badge-fail\">🚨 AUTHORIZATION REGRESSIONS DETECTED</div>");
        }

        sb.append("""
      </div>
    </div>

    <div class="meta-bar">
      <div class="meta-item">
        <span class="meta-label">Target Base URL</span>
        <span class="meta-val">""").append(escapeHtml(targetBaseUrl != null ? targetBaseUrl : "N/A")).append("""
</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Execution Run ID</span>
        <span class="meta-val">""").append(escapeHtml(runId != null ? runId : "N/A")).append("""
</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Audit Timestamp</span>
        <span class="meta-val">""").append(Instant.now().toString()).append("""
</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">OWASP Compliance Rate</span>
        <span class="meta-val">""").append(String.format("%.1f%%", passPct)).append("""
</span>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <span class="meta-label">Total Matrix Tests</span>
        <span class="kpi-num c-primary">""").append(total).append("""
</span>
      </div>
      <div class="kpi-card">
        <span class="meta-label">Passed Checks</span>
        <span class="kpi-num c-pass">""").append(passed).append("""
</span>
      </div>
      <div class="kpi-card">
        <span class="meta-label">BOLA / IDOR Violations</span>
        <span class="kpi-num c-danger">""").append(bola).append("""
</span>
      </div>
      <div class="kpi-card">
        <span class="meta-label">Unauthorized Regressions</span>
        <span class="kpi-num c-danger">""").append(regressions).append("""
</span>
      </div>
      <div class="kpi-card">
        <span class="meta-label">Data Leaks & Assertions</span>
        <span class="kpi-num c-warn">""").append(dataLeaks + assertionFailures).append("""
</span>
      </div>
    </div>
""");

        // Actionable Vulnerability Remediation Section
        if (!isCompliant && results != null) {
            sb.append("""
    <div class="section-title">🚨 Critical Authorization Findings & Automated Remediation</div>
""");
            for (MatrixResult r : results) {
                if (r.getVerdict() == Verdict.PASS) continue;

                String pillClass = (r.getVerdict() == Verdict.BOLA_IDOR_VULNERABILITY || r.getVerdict() == Verdict.REGRESSION_UNAUTHORIZED_ACCESS)
                        ? "pill-danger" : "pill-warn";

                sb.append("""
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-title">""").append(escapeHtml(r.getEndpointMethod().name())).append(" ").append(escapeHtml(r.getEndpointPath())).append(" &mdash; Role: ").append(escapeHtml(r.getRoleName())).append("""
</div>
        <span class="pill """).append(pillClass).append("\">").append(r.getVerdict().name()).append("""
</span>
      </div>
      <div class="finding-desc">
        Expected HTTP <strong>""").append(r.getExpectedStatus()).append("</strong> but received HTTP <strong>").append(r.getActualStatus()).append("</strong>.");

                if (r.getAssertionFailure() != null) {
                    sb.append(" Assertion Detail: ").append(escapeHtml(r.getAssertionFailure()));
                }
                if (r.getErrorMessage() != null) {
                    sb.append(" Error: ").append(escapeHtml(r.getErrorMessage()));
                }

                sb.append("</div>");

                // Include remediation snippet
                Map<String, String> remed = RemediationAdvisor.generateRemediation(
                        r.getVerdict(),
                        null,
                        r.getRoleName(),
                        r.getExpectedStatus(),
                        r.getActualStatus()
                );

                if (remed.containsKey("spring_boot")) {
                    sb.append("<div class=\"remed-tag\">Recommended Fix (Spring Security / Java)</div>");
                    sb.append("<div class=\"code-box\">").append(escapeHtml(remed.get("spring_boot"))).append("</div>");
                }
                if (remed.containsKey("express_js")) {
                    sb.append("<div class=\"remed-tag\">Recommended Fix (Node.js / Express)</div>");
                    sb.append("<div class=\"code-box\">").append(escapeHtml(remed.get("express_js"))).append("</div>");
                }

                sb.append("</div>");
            }
        }

        // Full Matrix Table
        sb.append("""
    <div class="section-title">📋 Complete Matrix Test Results</div>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Role</th>
            <th>Expected</th>
            <th>Actual</th>
            <th>Latency</th>
            <th>Verdict</th>
          </tr>
        </thead>
        <tbody>
""");

        if (results != null) {
            for (MatrixResult r : results) {
                String pillClass = switch (r.getVerdict()) {
                    case PASS -> "pill-pass";
                    case BOLA_IDOR_VULNERABILITY, REGRESSION_UNAUTHORIZED_ACCESS -> "pill-danger";
                    case REGRESSION_DATA_LEAKAGE, ASSERTION_FAILED -> "pill-warn";
                    default -> "pill-info";
                };

                sb.append("<tr>")
                  .append("<td class=\"code-cell\"><strong>").append(escapeHtml(r.getEndpointMethod().name())).append("</strong></td>")
                  .append("<td class=\"code-cell\">").append(escapeHtml(r.getEndpointPath())).append("</td>")
                  .append("<td>").append(escapeHtml(r.getRoleName())).append("</td>")
                  .append("<td class=\"code-cell\">").append(r.getExpectedStatus()).append("</td>")
                  .append("<td class=\"code-cell\">").append(r.getActualStatus()).append("</td>")
                  .append("<td>").append(r.getDurationMs()).append("ms</td>")
                  .append("<td><span class=\"pill ").append(pillClass).append("\">").append(r.getVerdict().name()).append("</span></td>")
                  .append("</tr>\n");
            }
        }

        sb.append("""
        </tbody>
      </table>
    </div>
    <div style="text-align: center; font-size: 12px; color: var(--text-muted); margin-top: 40px;">
      AuthMatrix Pro &bull; Enterprise Authorization Contract Testing &bull; 
      <a href="https://github.com/mamadox001/AuthMatrix_Pro" style="color: var(--primary); text-decoration: none;">GitHub Repository</a>
    </div>
  </div>
</body>
</html>
""");

        return sb.toString();
    }

    private static String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#39;");
    }
}
