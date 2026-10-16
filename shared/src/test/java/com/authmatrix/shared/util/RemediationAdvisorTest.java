package com.authmatrix.shared.util;

import com.authmatrix.shared.model.EndpointPolicy;
import com.authmatrix.shared.model.HttpMethod;
import com.authmatrix.shared.model.Verdict;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RemediationAdvisorTest {

    @Test
    void shouldGenerateActionableRemediationForBola() {
        EndpointPolicy ep = new EndpointPolicy("1", "Get Tenant", HttpMethod.GET, "/api/tenants/{tenantId}", Collections.emptyMap(), null, Collections.emptyMap(), null);
        Map<String, String> rem = RemediationAdvisor.generateRemediation(Verdict.BOLA_IDOR_VULNERABILITY, ep, "member_b", 403, 200);

        assertThat(rem).containsKey("spring_boot");
        assertThat(rem.get("spring_boot")).contains("@PreAuthorize");
        assertThat(rem).containsKey("express_js");
        assertThat(rem.get("express_js")).contains("req.user.tenantId");
        assertThat(rem).containsKey("fastapi");
        assertThat(rem.get("fastapi")).contains("verify_tenant_access");
        assertThat(rem).containsKey("golang");
        assertThat(rem.get("golang")).contains("claims.TenantID");
    }

    @Test
    void shouldGenerateActionableRemediationForBfla() {
        EndpointPolicy ep = new EndpointPolicy("2", "Admin Config", HttpMethod.DELETE, "/api/admin/system", Collections.emptyMap(), null, Collections.emptyMap(), null);
        Map<String, String> rem = RemediationAdvisor.generateRemediation(Verdict.REGRESSION_UNAUTHORIZED_ACCESS, ep, "guest", 401, 200);

        assertThat(rem.get("spring_boot")).contains("hasRole(\"ADMIN\")");
        assertThat(rem.get("express_js")).contains("requireRole");
    }
}
