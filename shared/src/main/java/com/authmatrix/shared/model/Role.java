package com.authmatrix.shared.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Role {
    private String id;

    @NotBlank
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Role name must only contain alphanumeric characters, underscores, and dashes")
    private String name;

    @JsonProperty("header_name")
    private String headerName = "Authorization";

    @JsonProperty("header_value")
    private String headerValue = "";

    @JsonProperty("auth_handler")
    private AuthHandler authHandler;

    @JsonProperty("params")
    private java.util.Map<String, String> params = new java.util.HashMap<>();

    @JsonProperty("created_at")
    private String createdAt;

    public Role() {}

    public Role(String id, String name, String headerName, String headerValue, String createdAt) {
        this(id, name, headerName, headerValue, null, null, createdAt);
    }

    public Role(String id, String name, String headerName, String headerValue,
                AuthHandler authHandler, java.util.Map<String, String> params, String createdAt) {
        this.id = id;
        this.name = name;
        this.headerName = headerName != null ? headerName : "Authorization";
        this.headerValue = headerValue != null ? headerValue : "";
        this.authHandler = authHandler;
        this.params = params != null ? params : new java.util.HashMap<>();
        this.createdAt = createdAt;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

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

    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Role role = (Role) o;
        return Objects.equals(id, role.id) &&
               Objects.equals(name, role.name) &&
               Objects.equals(headerName, role.headerName) &&
               Objects.equals(headerValue, role.headerValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, headerName, headerValue);
    }
}
