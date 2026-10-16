package com.authmatrix.shared.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthMatrixYaml {

    private String version = "1.0";

    @NotBlank
    @JsonProperty("target_base_url")
    private String targetBaseUrl;

    @NotNull
    private Map<String, YamlRole> roles = new HashMap<>();

    @NotNull
    private List<YamlEndpoint> endpoints = new ArrayList<>();

    public AuthMatrixYaml() {}

    public AuthMatrixYaml(String version, String targetBaseUrl, Map<String, YamlRole> roles, List<YamlEndpoint> endpoints) {
        this.version = version != null ? version : "1.0";
        this.targetBaseUrl = targetBaseUrl;
        this.roles = roles != null ? roles : new HashMap<>();
        this.endpoints = endpoints != null ? endpoints : new ArrayList<>();
    }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public String getTargetBaseUrl() { return targetBaseUrl; }
    public void setTargetBaseUrl(String targetBaseUrl) { this.targetBaseUrl = targetBaseUrl; }

    public Map<String, YamlRole> getRoles() { return roles; }
    public void setRoles(Map<String, YamlRole> roles) { this.roles = roles != null ? roles : new HashMap<>(); }

    public List<YamlEndpoint> getEndpoints() { return endpoints; }
    public void setEndpoints(List<YamlEndpoint> endpoints) { this.endpoints = endpoints != null ? endpoints : new ArrayList<>(); }

    public static class YamlRole {
        @JsonProperty("header_name")
        private String headerName = "Authorization";

        @JsonProperty("header_value")
        private String headerValue = "";

        public YamlRole() {}

        public YamlRole(String headerName, String headerValue) {
            this.headerName = headerName != null ? headerName : "Authorization";
            this.headerValue = headerValue != null ? headerValue : "";
        }

        public String getHeaderName() { return headerName; }
        public void setHeaderName(String headerName) { this.headerName = headerName; }

        public String getHeaderValue() { return headerValue; }
        public void setHeaderValue(String headerValue) { this.headerValue = headerValue; }
    }

    public static class YamlEndpoint {
        @NotBlank
        private String name;

        @NotNull
        private HttpMethod method = HttpMethod.GET;

        @NotBlank
        private String path = "/";

        private Map<String, String> headers = new HashMap<>();

        private Object body;

        @NotNull
        private Map<String, Integer> expect = new HashMap<>();

        public YamlEndpoint() {}

        public YamlEndpoint(String name, HttpMethod method, String path,
                            Map<String, String> headers, Object body, Map<String, Integer> expect) {
            this.name = name;
            this.method = method != null ? method : HttpMethod.GET;
            this.path = path != null ? path : "/";
            this.headers = headers != null ? headers : new HashMap<>();
            this.body = body;
            this.expect = expect != null ? expect : new HashMap<>();
        }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public HttpMethod getMethod() { return method; }
        public void setMethod(HttpMethod method) { this.method = method; }

        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }

        public Map<String, String> getHeaders() { return headers; }
        public void setHeaders(Map<String, String> headers) { this.headers = headers != null ? headers : new HashMap<>(); }

        public Object getBody() { return body; }
        public void setBody(Object body) { this.body = body; }

        public Map<String, Integer> getExpect() { return expect; }
        public void setExpect(Map<String, Integer> expect) { this.expect = expect != null ? expect : new HashMap<>(); }
    }
}
