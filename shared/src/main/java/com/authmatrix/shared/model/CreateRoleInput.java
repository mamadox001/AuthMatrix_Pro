package com.authmatrix.shared.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class CreateRoleInput {
    @NotBlank
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Role name must only contain alphanumeric characters, underscores, and dashes")
    private String name;

    @JsonProperty("header_name")
    @com.fasterxml.jackson.annotation.JsonAlias({"headerName", "header_name"})
    private String headerName = "Authorization";

    @JsonProperty("header_value")
    @com.fasterxml.jackson.annotation.JsonAlias({"headerValue", "header_value"})
    private String headerValue = "";

    @JsonProperty("auth_handler")
    @com.fasterxml.jackson.annotation.JsonAlias({"authHandler", "auth_handler"})
    private AuthHandler authHandler;

    @JsonProperty("params")
    private java.util.Map<String, String> params = new java.util.HashMap<>();

    public CreateRoleInput() {}

    public CreateRoleInput(String name, String headerName, String headerValue) {
        this(name, headerName, headerValue, null, null);
    }

    public CreateRoleInput(String name, String headerName, String headerValue,
                           AuthHandler authHandler, java.util.Map<String, String> params) {
        this.name = name;
        this.headerName = headerName != null ? headerName : "Authorization";
        this.headerValue = headerValue != null ? headerValue : "";
        this.authHandler = authHandler;
        this.params = params != null ? params : new java.util.HashMap<>();
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getHeaderName() { return headerName; }
    public void setHeaderName(String headerName) { this.headerName = headerName; }

    public String getHeaderValue() { return headerValue; }
    public void setHeaderValue(String headerValue) { this.headerValue = headerValue; }

    public AuthHandler getAuthHandler() { return authHandler; }
    public void setAuthHandler(AuthHandler authHandler) { this.authHandler = authHandler; }

    public java.util.Map<String, String> getParams() { return params; }
    public void setParams(java.util.Map<String, String> params) { this.params = params != null ? params : new java.util.HashMap<>(); }
}
