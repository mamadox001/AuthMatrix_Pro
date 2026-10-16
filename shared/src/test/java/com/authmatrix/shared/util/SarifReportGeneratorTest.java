package com.authmatrix.shared.util;

import com.authmatrix.shared.model.HttpMethod;
import com.authmatrix.shared.model.MatrixResult;
import com.authmatrix.shared.model.Verdict;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SarifReportGeneratorTest {

    @Test
    void shouldGenerateValidSarifV210Json() throws Exception {
        MatrixResult r1 = new MatrixResult(
                "id-1", "run-101", "ep-1", "Get Org Data",
                HttpMethod.GET, "/api/v1/orgs/{orgId}/billing", "guest",
                401, 200, 512, 12, Verdict.REGRESSION_UNAUTHORIZED_ACCESS,
                null, null, false, Collections.emptyMap(), "2026-10-16T12:00:00Z"
        );

        MatrixResult r2 = new MatrixResult(
                "id-2", "run-101", "ep-2", "Access Tenant Docs",
                HttpMethod.GET, "/api/v1/tenants/{tenantId}/docs", "member_a",
                403, 200, 1024, 15, Verdict.BOLA_IDOR_VULNERABILITY,
                null, "BOLA detected on cross-tenant access", true, Collections.emptyMap(), "2026-10-16T12:00:00Z"
        );

        String sarifJson = SarifReportGenerator.generateSarif("run-101", List.of(r1, r2), "http://127.0.0.1:3000");

        JsonNode root = JsonUtils.getJsonMapper().readTree(sarifJson);

        assertThat(root.get("version").asText()).isEqualTo("2.1.0");
        assertThat(root.get("runs")).isNotEmpty();

        JsonNode run = root.get("runs").get(0);
        assertThat(run.get("tool").get("driver").get("name").asText()).isEqualTo("AuthMatrix Pro");

        JsonNode rules = run.get("tool").get("driver").get("rules");
        assertThat(rules).hasSize(5);

        JsonNode findings = run.get("results");
        assertThat(findings).hasSize(2);

        JsonNode finding1 = findings.get(0);
        assertThat(finding1.get("ruleId").asText()).isEqualTo("AUTH002");
        assertThat(finding1.get("level").asText()).isEqualTo("error");

        JsonNode finding2 = findings.get(1);
        assertThat(finding2.get("ruleId").asText()).isEqualTo("AUTH001");
        assertThat(finding2.get("level").asText()).isEqualTo("error");
    }
}
