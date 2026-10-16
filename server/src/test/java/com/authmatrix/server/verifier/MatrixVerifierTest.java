package com.authmatrix.server.verifier;

import com.authmatrix.server.db.DatabaseManager;
import com.authmatrix.server.service.WebhookDispatcher;
import com.authmatrix.shared.model.*;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

class MatrixVerifierTest {

    private static HttpServer mockServer;
    private static int mockPort;

    @BeforeAll
    static void startMockServer() throws Exception {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        mockPort = mockServer.getAddress().getPort();

        // 1. Login endpoint for dynamic auth handlers
        mockServer.createContext("/api/auth/login", exchange -> {
            byte[] res = "{\"token\":\"refreshed-jwt-secret-xyz\",\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, res.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(res); }
        });

        // 2. Sensitive endpoint leaking data
        mockServer.createContext("/api/v1/user/profile", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth == null || !auth.contains("Bearer")) {
                byte[] res = "{\"error\":\"unauthorized\"}".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(401, res.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(res); }
                return;
            }
            byte[] res = "{\"username\":\"alice\",\"ssn\":\"000-12-3456\",\"secret_token\":\"leak-123\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, res.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(res); }
        });

        // 3. Multi-tenant document endpoint with BOLA vulnerability
        mockServer.createContext("/api/v1/tenants/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            // Insecure BOLA simulation: Always returns 200 OK regardless of who requested it!
            byte[] res = ("{\"tenantId\":\"" + path + "\",\"documents\":[\"payroll.pdf\"]}").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, res.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(res); }
        });

        mockServer.start();
    }

    @AfterAll
    static void stopMockServer() {
        if (mockServer != null) mockServer.stop(0);
    }

    @Test
    void shouldDetectDataLeakageViaAssertions(@TempDir File tempDir) {
        DatabaseManager db = new DatabaseManager(new File(tempDir, "test.db").getAbsolutePath());
        MatrixVerifier verifier = new MatrixVerifier(db, new WebhookDispatcher());

        String targetUrl = "http://127.0.0.1:" + mockPort;

        PolicyAssertion assertion = new PolicyAssertion();
        assertion.setBodyMustNotContain(List.of("ssn", "secret_token"));

        EndpointPolicy ep = new EndpointPolicy(
                "ep-leak", "User Profile", HttpMethod.GET, "/api/v1/user/profile",
                Collections.emptyMap(), null, Map.of("member", 200), assertion, "2026-10-16"
        );

        Role role = new Role("r1", "member", "Authorization", "Bearer valid-token", null, null, "2026-10-16");

        DatabaseManager.MatrixRunResult runResult = verifier.evaluateMatrix(targetUrl, List.of(ep), List.of(role), 5000);

        assertThat(runResult.results()).hasSize(1);
        MatrixResult res = runResult.results().get(0);
        assertThat(res.getVerdict()).isEqualTo(Verdict.REGRESSION_DATA_LEAKAGE);
        assertThat(res.getAssertionFailure()).contains("ssn");
    }

    @Test
    void shouldDetectBolaCrossTenantAccess(@TempDir File tempDir) {
        DatabaseManager db = new DatabaseManager(new File(tempDir, "test_bola.db").getAbsolutePath());
        MatrixVerifier verifier = new MatrixVerifier(db, new WebhookDispatcher());

        String targetUrl = "http://127.0.0.1:" + mockPort;

        EndpointPolicy ep = new EndpointPolicy(
                "ep-tenant", "Tenant Docs", HttpMethod.GET, "/api/v1/tenants/{tenantId}/docs",
                Collections.emptyMap(), null, Map.of("tenant_a", 200, "tenant_b", 200), null, "2026-10-16"
        );

        Role roleA = new Role("ra", "tenant_a", "Authorization", "Bearer token-a", null, Map.of("tenantId", "tenant-100"), "2026-10-16");
        Role roleB = new Role("rb", "tenant_b", "Authorization", "Bearer token-b", null, Map.of("tenantId", "tenant-200"), "2026-10-16");

        DatabaseManager.MatrixRunResult runResult = verifier.evaluateMatrix(targetUrl, List.of(ep), List.of(roleA, roleB), 5000);

        // One of the evaluations should flag BOLA_IDOR_VULNERABILITY because tenant A accessed tenant B's path
        boolean hasBola = runResult.results().stream().anyMatch(r -> r.getVerdict() == Verdict.BOLA_IDOR_VULNERABILITY);
        assertThat(hasBola).isTrue();
    }

    @Test
    void shouldAutoRefreshExpiringAuthToken(@TempDir File tempDir) {
        DatabaseManager db = new DatabaseManager(new File(tempDir, "test_auth.db").getAbsolutePath());
        MatrixVerifier verifier = new MatrixVerifier(db, new WebhookDispatcher());

        String targetUrl = "http://127.0.0.1:" + mockPort;

        AuthHandler handler = new AuthHandler(
                true, "/api/auth/login", HttpMethod.POST, Collections.emptyMap(),
                "{\"username\":\"admin\",\"password\":\"pass\"}", "token", "Bearer ", 300, null
        );

        Role role = new Role("r-auth", "admin_dynamic", "Authorization", "", handler, Collections.emptyMap(), "2026-10-16");

        EndpointPolicy ep = new EndpointPolicy(
                "ep-profile", "Profile", HttpMethod.GET, "/api/v1/user/profile",
                Collections.emptyMap(), null, Map.of("admin_dynamic", 200), null, "2026-10-16"
        );

        DatabaseManager.MatrixRunResult runResult = verifier.evaluateMatrix(targetUrl, List.of(ep), List.of(role), 5000);

        assertThat(runResult.results()).hasSize(1);
        MatrixResult res = runResult.results().get(0);
        // The token was refreshed before calling, so the mock returned 200 OK!
        assertThat(res.getActualStatus()).isEqualTo(200);
        assertThat(role.getHeaderValue()).isEqualTo("Bearer refreshed-jwt-secret-xyz");
    }
}
