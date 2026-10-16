package com.authmatrix.shared.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TrafficLog {
    private String id;
    private String method;
    private String url;
    private String path;

    @JsonProperty("request_headers")
    private Map<String, Object> requestHeaders = new HashMap<>();

    @JsonProperty("request_body")
    private String requestBody;

    @JsonProperty("response_status")
    private int responseStatus;

    @JsonProperty("response_headers")
    private Map<String, Object> responseHeaders = new HashMap<>();

    @JsonProperty("response_body")
    private String responseBody;

    @JsonProperty("duration_ms")
    private long durationMs;

    @JsonProperty("captured_at")
    private String capturedAt;

    public TrafficLog() {}

    public TrafficLog(String id, String method, String url, String path,
                      Map<String, Object> requestHeaders, String requestBody,
                      int responseStatus, Map<String, Object> responseHeaders,
                      String responseBody, long durationMs, String capturedAt) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.path = path;
        this.requestHeaders = requestHeaders != null ? requestHeaders : new HashMap<>();
        this.requestBody = requestBody;
        this.responseStatus = responseStatus;
        this.responseHeaders = responseHeaders != null ? responseHeaders : new HashMap<>();
        this.responseBody = responseBody;
        this.durationMs = durationMs;
        this.capturedAt = capturedAt;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public Map<String, Object> getRequestHeaders() { return requestHeaders; }
    public void setRequestHeaders(Map<String, Object> requestHeaders) { this.requestHeaders = requestHeaders != null ? requestHeaders : new HashMap<>(); }

    public String getRequestBody() { return requestBody; }
    public void setRequestBody(String requestBody) { this.requestBody = requestBody; }

    public int getResponseStatus() { return responseStatus; }
    public void setResponseStatus(int responseStatus) { this.responseStatus = responseStatus; }

    public Map<String, Object> getResponseHeaders() { return responseHeaders; }
    public void setResponseHeaders(Map<String, Object> responseHeaders) { this.responseHeaders = responseHeaders != null ? responseHeaders : new HashMap<>(); }

    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }

    public long getDurationMs() { return durationMs; }
    public void setDurationMs(long durationMs) { this.durationMs = durationMs; }

    public String getCapturedAt() { return capturedAt; }
    public void setCapturedAt(String capturedAt) { this.capturedAt = capturedAt; }
}
