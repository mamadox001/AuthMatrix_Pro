package com.authmatrix.shared.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.HashMap;
import java.util.Map;

public class CreateEndpointPolicyInput {
    @NotBlank
    private String name;

    @NotNull
    private HttpMethod method = HttpMethod.GET;

    @NotBlank
    private String path = "/";

    private Map<String, String> headers = new HashMap<>();

    private String body;

    private Map<String, Integer> expect = new HashMap<>();

    public CreateEndpointPolicyInput() {}

    public CreateEndpointPolicyInput(String name, HttpMethod method, String path,
                                     Map<String, String> headers, String body,
                                     Map<String, Integer> expect) {
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

    public String getBody() { return body; }
    public void setBody(String body) { this.body = body; }

    public Map<String, Integer> getExpect() { return expect; }
    public void setExpect(Map<String, Integer> expect) { this.expect = expect != null ? expect : new HashMap<>(); }
}
