package com.authmatrix.shared.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class MatrixResult {
    private String id;

    @JsonProperty("run_id")
    private String runId;

    @JsonProperty("endpoint_id")
    private String endpointId;

    @JsonProperty("endpoint_name")
    private String endpointName;

    @JsonProperty("endpoint_method")
    private HttpMethod endpointMethod;

    @JsonProperty("endpoint_path")
    private String endpointPath;

    @JsonProperty("role_name")
    private String roleName;

    @JsonProperty("expected_status")
    private int expectedStatus;

    @JsonProperty("actual_status")
    private int actualStatus;

    @JsonProperty("response_bytes")
    private long responseBytes;

    @JsonProperty("duration_ms")
    private long durationMs;

    private Verdict verdict;

    @JsonProperty("error_message")
    private String errorMessage;

    @JsonProperty("assertion_failure")
    private String assertionFailure;

    @JsonProperty("bola_detected")
    private boolean bolaDetected;

    @JsonProperty("remediation")
    private java.util.Map<String, String> remediation = new java.util.HashMap<>();

    @JsonProperty("evaluated_at")
    private String evaluatedAt;

    public MatrixResult() {}

    public MatrixResult(String id, String runId, String endpointId, String endpointName,
                        HttpMethod endpointMethod, String endpointPath, String roleName,
                        int expectedStatus, int actualStatus, long responseBytes,
                        long durationMs, Verdict verdict, String errorMessage, String evaluatedAt) {
        this(id, runId, endpointId, endpointName, endpointMethod, endpointPath, roleName,
                expectedStatus, actualStatus, responseBytes, durationMs, verdict, errorMessage,
                null, false, null, evaluatedAt);
    }

    public MatrixResult(String id, String runId, String endpointId, String endpointName,
                        HttpMethod endpointMethod, String endpointPath, String roleName,
                        int expectedStatus, int actualStatus, long responseBytes,
                        long durationMs, Verdict verdict, String errorMessage,
                        String assertionFailure, boolean bolaDetected,
                        java.util.Map<String, String> remediation, String evaluatedAt) {
        this.id = id;
        this.runId = runId;
        this.endpointId = endpointId;
        this.endpointName = endpointName;
        this.endpointMethod = endpointMethod;
        this.endpointPath = endpointPath;
        this.roleName = roleName;
        this.expectedStatus = expectedStatus;
        this.actualStatus = actualStatus;
        this.responseBytes = responseBytes;
        this.durationMs = durationMs;
        this.verdict = verdict;
        this.errorMessage = errorMessage;
        this.assertionFailure = assertionFailure;
        this.bolaDetected = bolaDetected;
        this.remediation = remediation != null ? remediation : new java.util.HashMap<>();
        this.evaluatedAt = evaluatedAt;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRunId() { return runId; }
    public void setRunId(String runId) { this.runId = runId; }

    public String getEndpointId() { return endpointId; }
    public void setEndpointId(String endpointId) { this.endpointId = endpointId; }

    public String getEndpointName() { return endpointName; }
    public void setEndpointName(String endpointName) { this.endpointName = endpointName; }

    public HttpMethod getEndpointMethod() { return endpointMethod; }
    public void setEndpointMethod(HttpMethod endpointMethod) { this.endpointMethod = endpointMethod; }

    public String getEndpointPath() { return endpointPath; }
    public void setEndpointPath(String endpointPath) { this.endpointPath = endpointPath; }

    public String getRoleName() { return roleName; }
    public void setRoleName(String roleName) { this.roleName = roleName; }

    public int getExpectedStatus() { return expectedStatus; }
    public void setExpectedStatus(int expectedStatus) { this.expectedStatus = expectedStatus; }

    public int getActualStatus() { return actualStatus; }
    public void setActualStatus(int actualStatus) { this.actualStatus = actualStatus; }

    public long getResponseBytes() { return responseBytes; }
    public void setResponseBytes(long responseBytes) { this.responseBytes = responseBytes; }

    public long getDurationMs() { return durationMs; }
    public void setDurationMs(long durationMs) { this.durationMs = durationMs; }

    public Verdict getVerdict() { return verdict; }
    public void setVerdict(Verdict verdict) { this.verdict = verdict; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public String getEvaluatedAt() { return evaluatedAt; }
    public void setEvaluatedAt(String evaluatedAt) { this.evaluatedAt = evaluatedAt; }

    @JsonProperty("role")
    public String getRole() { return roleName; }

    @JsonProperty("method")
    public String getMethod() { return endpointMethod != null ? endpointMethod.name() : "GET"; }

    @JsonProperty("path")
    public String getPath() { return endpointPath; }

    @JsonProperty("name")
    public String getName() { return endpointName; }

    public String getAssertionFailure() { return assertionFailure; }
    public void setAssertionFailure(String assertionFailure) { this.assertionFailure = assertionFailure; }

    public boolean isBolaDetected() { return bolaDetected; }
    public void setBolaDetected(boolean bolaDetected) { this.bolaDetected = bolaDetected; }

    public java.util.Map<String, String> getRemediation() { return remediation; }
    public void setRemediation(java.util.Map<String, String> remediation) { this.remediation = remediation != null ? remediation : new java.util.HashMap<>(); }
}
