package com.authmatrix.server.db;

import com.authmatrix.shared.model.*;
import com.authmatrix.shared.util.JsonUtils;
import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.sql.*;
import java.time.Instant;
import java.util.*;

@Repository
public class DatabaseManager {

    private final String dbUrl;

    public DatabaseManager(@Value("${authmatrix.db-path:authmatrix.db}") String dbPath) {
        String envDbPath = System.getenv("DB_PATH");
        if (envDbPath != null && !envDbPath.isBlank()) {
            dbPath = envDbPath;
        }
        this.dbUrl = "jdbc:sqlite:" + dbPath;
        initDatabase();
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(dbUrl);
    }

    private void initDatabase() {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA journal_mode = WAL;");
            stmt.execute("PRAGMA foreign_keys = ON;");

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                  id TEXT PRIMARY KEY,
                  method TEXT NOT NULL,
                  url TEXT NOT NULL,
                  path TEXT NOT NULL,
                  request_headers TEXT NOT NULL,
                  request_body TEXT,
                  response_status INTEGER NOT NULL,
                  response_headers TEXT NOT NULL,
                  response_body TEXT,
                  duration_ms INTEGER NOT NULL,
                  captured_at TEXT NOT NULL
                );
            """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_traffic_captured_at ON traffic_logs(captured_at DESC);");

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS auth_roles (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL UNIQUE,
                  header_name TEXT NOT NULL,
                  header_value TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS endpoint_policies (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  method TEXT NOT NULL,
                  path TEXT NOT NULL,
                  headers_json TEXT NOT NULL,
                  body_text TEXT,
                  expect_json TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS matrix_results (
                  id TEXT PRIMARY KEY,
                  run_id TEXT NOT NULL,
                  endpoint_id TEXT NOT NULL,
                  endpoint_name TEXT NOT NULL,
                  endpoint_method TEXT NOT NULL,
                  endpoint_path TEXT NOT NULL,
                  role_name TEXT NOT NULL,
                  expected_status INTEGER NOT NULL,
                  actual_status INTEGER NOT NULL,
                  response_bytes INTEGER NOT NULL,
                  duration_ms INTEGER NOT NULL,
                  verdict TEXT NOT NULL,
                  error_message TEXT,
                  evaluated_at TEXT NOT NULL
                );
            """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_matrix_run_id ON matrix_results(run_id);");

            // Seed default roles if empty
            try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM auth_roles")) {
                if (rs.next() && rs.getInt(1) == 0) {
                    seedDefaultRoles(conn);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize SQLite database: " + e.getMessage(), e);
        }
    }

    private void seedDefaultRoles(Connection conn) throws SQLException {
        String now = Instant.now().toString();
        String sql = "INSERT INTO auth_roles (id, name, header_name, header_value, created_at) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            // admin
            ps.setString(1, UUID.randomUUID().toString());
            ps.setString(2, "admin");
            ps.setString(3, "Authorization");
            ps.setString(4, "Bearer admin-token-secret");
            ps.setString(5, now);
            ps.addBatch();

            // member_a
            ps.setString(1, UUID.randomUUID().toString());
            ps.setString(2, "member_a");
            ps.setString(3, "Authorization");
            ps.setString(4, "Bearer member-a-token");
            ps.setString(5, now);
            ps.addBatch();

            // guest
            ps.setString(1, UUID.randomUUID().toString());
            ps.setString(2, "guest");
            ps.setString(3, "Authorization");
            ps.setString(4, "");
            ps.setString(5, now);
            ps.addBatch();

            ps.executeBatch();
        }
    }

    // Traffic Logs
    public synchronized void insertTrafficLog(TrafficLog log) {
        String sql = """
            INSERT INTO traffic_logs
            (id, method, url, path, request_headers, request_body, response_status, response_headers, response_body, duration_ms, captured_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, log.getId());
            ps.setString(2, log.getMethod());
            ps.setString(3, log.getUrl());
            ps.setString(4, log.getPath());
            ps.setString(5, JsonUtils.toJson(log.getRequestHeaders()));
            ps.setString(6, log.getRequestBody());
            ps.setInt(7, log.getResponseStatus());
            ps.setString(8, JsonUtils.toJson(log.getResponseHeaders()));
            ps.setString(9, log.getResponseBody());
            ps.setLong(10, log.getDurationMs());
            ps.setString(11, log.getCapturedAt());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Error inserting traffic log: " + e.getMessage(), e);
        }
    }

    public synchronized List<TrafficLog> listTrafficLogs(int limit) {
        String sql = "SELECT * FROM traffic_logs ORDER BY captured_at DESC LIMIT ?";
        List<TrafficLog> logs = new ArrayList<>();
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit > 0 ? limit : 200);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> reqHeaders = JsonUtils.getJsonMapper().readValue(
                            rs.getString("request_headers"),
                            new TypeReference<Map<String, Object>>() {}
                    );
                    Map<String, Object> resHeaders = JsonUtils.getJsonMapper().readValue(
                            rs.getString("response_headers"),
                            new TypeReference<Map<String, Object>>() {}
                    );
                    logs.add(new TrafficLog(
                            rs.getString("id"),
                            rs.getString("method"),
                            rs.getString("url"),
                            rs.getString("path"),
                            reqHeaders,
                            rs.getString("request_body"),
                            rs.getInt("response_status"),
                            resHeaders,
                            rs.getString("response_body"),
                            rs.getLong("duration_ms"),
                            rs.getString("captured_at")
                    ));
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Error listing traffic logs: " + e.getMessage(), e);
        }
        return logs;
    }

    public synchronized void clearTrafficLogs() {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("DELETE FROM traffic_logs");
        } catch (SQLException e) {
            throw new RuntimeException("Error clearing traffic logs: " + e.getMessage(), e);
        }
    }

    // Roles
    public synchronized List<Role> listRoles() {
        String sql = "SELECT id, name, header_name, header_value, created_at FROM auth_roles ORDER BY created_at ASC";
        List<Role> roles = new ArrayList<>();
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                roles.add(new Role(
                        rs.getString("id"),
                        rs.getString("name"),
                        rs.getString("header_name"),
                        rs.getString("header_value"),
                        rs.getString("created_at")
                ));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Error listing roles: " + e.getMessage(), e);
        }
        return roles;
    }

    public synchronized Role upsertRole(CreateRoleInput input) {
        String existingSql = "SELECT id, created_at FROM auth_roles WHERE name = ?";
        try (Connection conn = getConnection()) {
            String existingId = null;
            String createdAt = null;
            try (PreparedStatement ps = conn.prepareStatement(existingSql)) {
                ps.setString(1, input.getName());
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        existingId = rs.getString("id");
                        createdAt = rs.getString("created_at");
                    }
                }
            }

            if (existingId != null) {
                String updateSql = "UPDATE auth_roles SET header_name = ?, header_value = ? WHERE id = ?";
                try (PreparedStatement ps = conn.prepareStatement(updateSql)) {
                    ps.setString(1, input.getHeaderName());
                    ps.setString(2, input.getHeaderValue());
                    ps.setString(3, existingId);
                    ps.executeUpdate();
                }
                return new Role(existingId, input.getName(), input.getHeaderName(), input.getHeaderValue(), createdAt);
            } else {
                String insertSql = "INSERT INTO auth_roles (id, name, header_name, header_value, created_at) VALUES (?, ?, ?, ?, ?)";
                String newId = UUID.randomUUID().toString();
                String now = Instant.now().toString();
                try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                    ps.setString(1, newId);
                    ps.setString(2, input.getName());
                    ps.setString(3, input.getHeaderName());
                    ps.setString(4, input.getHeaderValue());
                    ps.setString(5, now);
                    ps.executeUpdate();
                }
                return new Role(newId, input.getName(), input.getHeaderName(), input.getHeaderValue(), now);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Error upserting role: " + e.getMessage(), e);
        }
    }

    public synchronized void deleteRole(String id) {
        String sql = "DELETE FROM auth_roles WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Error deleting role: " + e.getMessage(), e);
        }
    }

    // Endpoints
    public synchronized List<EndpointPolicy> listEndpoints() {
        String sql = "SELECT * FROM endpoint_policies ORDER BY created_at ASC";
        List<EndpointPolicy> endpoints = new ArrayList<>();
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                Map<String, String> headers = JsonUtils.getJsonMapper().readValue(
                        rs.getString("headers_json"),
                        new TypeReference<Map<String, String>>() {}
                );
                Map<String, Integer> expect = JsonUtils.getJsonMapper().readValue(
                        rs.getString("expect_json"),
                        new TypeReference<Map<String, Integer>>() {}
                );
                endpoints.add(new EndpointPolicy(
                        rs.getString("id"),
                        rs.getString("name"),
                        HttpMethod.fromString(rs.getString("method")),
                        rs.getString("path"),
                        headers,
                        rs.getString("body_text"),
                        expect,
                        rs.getString("created_at")
                ));
            }
        } catch (Exception e) {
            throw new RuntimeException("Error listing endpoint policies: " + e.getMessage(), e);
        }
        return endpoints;
    }

    public synchronized EndpointPolicy createEndpoint(CreateEndpointPolicyInput input) {
        String sql = "INSERT INTO endpoint_policies (id, name, method, path, headers_json, body_text, expect_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        String id = UUID.randomUUID().toString();
        String now = Instant.now().toString();
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setString(2, input.getName());
            ps.setString(3, input.getMethod().name());
            ps.setString(4, input.getPath());
            ps.setString(5, JsonUtils.toJson(input.getHeaders()));
            ps.setString(6, input.getBody());
            ps.setString(7, JsonUtils.toJson(input.getExpect()));
            ps.setString(8, now);
            ps.executeUpdate();
            return new EndpointPolicy(id, input.getName(), input.getMethod(), input.getPath(), input.getHeaders(), input.getBody(), input.getExpect(), now);
        } catch (SQLException e) {
            throw new RuntimeException("Error creating endpoint policy: " + e.getMessage(), e);
        }
    }

    public synchronized EndpointPolicy updateEndpoint(String id, CreateEndpointPolicyInput input) {
        String sql = "UPDATE endpoint_policies SET name = ?, method = ?, path = ?, headers_json = ?, body_text = ?, expect_json = ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, input.getName());
            ps.setString(2, input.getMethod().name());
            ps.setString(3, input.getPath());
            ps.setString(4, JsonUtils.toJson(input.getHeaders()));
            ps.setString(5, input.getBody());
            ps.setString(6, JsonUtils.toJson(input.getExpect()));
            ps.setString(7, id);
            ps.executeUpdate();
            return new EndpointPolicy(id, input.getName(), input.getMethod(), input.getPath(), input.getHeaders(), input.getBody(), input.getExpect(), null);
        } catch (SQLException e) {
            throw new RuntimeException("Error updating endpoint policy: " + e.getMessage(), e);
        }
    }

    public synchronized void deleteEndpoint(String id) {
        String sql = "DELETE FROM endpoint_policies WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Error deleting endpoint policy: " + e.getMessage(), e);
        }
    }

    // Matrix Results
    public synchronized void insertMatrixResults(List<MatrixResult> results) {
        String sql = """
            INSERT INTO matrix_results
            (id, run_id, endpoint_id, endpoint_name, endpoint_method, endpoint_path, role_name, expected_status, actual_status, response_bytes, duration_ms, verdict, error_message, evaluated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            for (MatrixResult r : results) {
                ps.setString(1, r.getId());
                ps.setString(2, r.getRunId());
                ps.setString(3, r.getEndpointId());
                ps.setString(4, r.getEndpointName());
                ps.setString(5, r.getEndpointMethod().name());
                ps.setString(6, r.getEndpointPath());
                ps.setString(7, r.getRoleName());
                ps.setInt(8, r.getExpectedStatus());
                ps.setInt(9, r.getActualStatus());
                ps.setLong(10, r.getResponseBytes());
                ps.setLong(11, r.getDurationMs());
                ps.setString(12, r.getVerdict().name());
                ps.setString(13, r.getErrorMessage());
                ps.setString(14, r.getEvaluatedAt());
                ps.addBatch();
            }
            ps.executeBatch();
        } catch (SQLException e) {
            throw new RuntimeException("Error inserting matrix results: " + e.getMessage(), e);
        }
    }

    public synchronized MatrixRunResult getLatestMatrixResults() {
        String runIdSql = "SELECT run_id FROM matrix_results ORDER BY evaluated_at DESC LIMIT 1";
        String latestRunId = null;
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(runIdSql)) {
            if (rs.next()) {
                latestRunId = rs.getString("run_id");
            }
        } catch (SQLException e) {
            throw new RuntimeException("Error fetching latest run_id: " + e.getMessage(), e);
        }

        if (latestRunId == null) {
            return new MatrixRunResult(null, Collections.emptyList());
        }

        String resultsSql = "SELECT * FROM matrix_results WHERE run_id = ? ORDER BY endpoint_name ASC, role_name ASC";
        List<MatrixResult> results = new ArrayList<>();
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(resultsSql)) {
            ps.setString(1, latestRunId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    results.add(new MatrixResult(
                            rs.getString("id"),
                            rs.getString("run_id"),
                            rs.getString("endpoint_id"),
                            rs.getString("endpoint_name"),
                            HttpMethod.fromString(rs.getString("endpoint_method")),
                            rs.getString("endpoint_path"),
                            rs.getString("role_name"),
                            rs.getInt("expected_status"),
                            rs.getInt("actual_status"),
                            rs.getLong("response_bytes"),
                            rs.getLong("duration_ms"),
                            Verdict.valueOf(rs.getString("verdict")),
                            rs.getString("error_message"),
                            rs.getString("evaluated_at")
                    ));
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Error fetching matrix results: " + e.getMessage(), e);
        }

        return new MatrixRunResult(latestRunId, results);
    }

    public synchronized void clearEndpoints() {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("DELETE FROM endpoint_policies");
        } catch (SQLException e) {
            throw new RuntimeException("Error clearing endpoints: " + e.getMessage(), e);
        }
    }

    public synchronized void clearRoles() {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("DELETE FROM auth_roles");
            seedDefaultRoles(conn);
        } catch (SQLException e) {
            throw new RuntimeException("Error clearing roles: " + e.getMessage(), e);
        }
    }

    public synchronized void clearMatrixResults() {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("DELETE FROM matrix_results");
        } catch (SQLException e) {
            throw new RuntimeException("Error clearing matrix results: " + e.getMessage(), e);
        }
    }

    public record MatrixRunResult(String runId, List<MatrixResult> results) {}
}
