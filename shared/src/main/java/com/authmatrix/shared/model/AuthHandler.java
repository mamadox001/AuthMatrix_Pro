package com.authmatrix.shared.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthHandler {

    private boolean enabled = false;

    @JsonProperty("login_url")
    private String loginUrl;

    @JsonProperty("login_method")
    private HttpMethod loginMethod = HttpMethod.POST;

    @JsonProperty("login_headers")
    private Map<String, String> loginHeaders = new HashMap<>();

    @JsonProperty("login_body")
    private String loginBody;

    @JsonProperty("token_path")
    private String tokenPath = "token";

    @JsonProperty("token_prefix")
    private String tokenPrefix = "Bearer ";

    @JsonProperty("cache_ttl_seconds")
    private long cacheTtlSeconds = 300;

    @JsonProperty("last_refreshed_at")
    private String lastRefreshedAt;

    public AuthHandler() {}

    public AuthHandler(boolean enabled, String loginUrl, HttpMethod loginMethod,
                       Map<String, String> loginHeaders, String loginBody,
                       String tokenPath, String tokenPrefix, long cacheTtlSeconds,
                       String lastRefreshedAt) {
        this.enabled = enabled;
        this.loginUrl = loginUrl;
        this.loginMethod = loginMethod != null ? loginMethod : HttpMethod.POST;
        this.loginHeaders = loginHeaders != null ? loginHeaders : new HashMap<>();
        this.loginBody = loginBody;
        this.tokenPath = tokenPath != null ? tokenPath : "token";
        this.tokenPrefix = tokenPrefix != null ? tokenPrefix : "Bearer ";
        this.cacheTtlSeconds = cacheTtlSeconds > 0 ? cacheTtlSeconds : 300;
        this.lastRefreshedAt = lastRefreshedAt;
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getLoginUrl() { return loginUrl; }
    public void setLoginUrl(String loginUrl) { this.loginUrl = loginUrl; }

    public HttpMethod getLoginMethod() { return loginMethod; }
    public void setLoginMethod(HttpMethod loginMethod) { this.loginMethod = loginMethod; }

    public Map<String, String> getLoginHeaders() { return loginHeaders; }
    public void setLoginHeaders(Map<String, String> loginHeaders) { this.loginHeaders = loginHeaders != null ? loginHeaders : new HashMap<>(); }

    public String getLoginBody() { return loginBody; }
    public void setLoginBody(String loginBody) { this.loginBody = loginBody; }

    public String getTokenPath() { return tokenPath; }
    public void setTokenPath(String tokenPath) { this.tokenPath = tokenPath; }

    public String getTokenPrefix() { return tokenPrefix; }
    public void setTokenPrefix(String tokenPrefix) { this.tokenPrefix = tokenPrefix; }

    public long getCacheTtlSeconds() { return cacheTtlSeconds; }
    public void setCacheTtlSeconds(long cacheTtlSeconds) { this.cacheTtlSeconds = cacheTtlSeconds; }

    public String getLastRefreshedAt() { return lastRefreshedAt; }
    public void setLastRefreshedAt(String lastRefreshedAt) { this.lastRefreshedAt = lastRefreshedAt; }
}
