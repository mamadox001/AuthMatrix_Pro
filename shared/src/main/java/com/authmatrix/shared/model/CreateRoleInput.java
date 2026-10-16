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

    public CreateRoleInput() {}

    public CreateRoleInput(String name, String headerName, String headerValue) {
        this.name = name;
        this.headerName = headerName != null ? headerName : "Authorization";
        this.headerValue = headerValue != null ? headerValue : "";
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getHeaderName() { return headerName; }
    public void setHeaderName(String headerName) { this.headerName = headerName; }

    public String getHeaderValue() { return headerValue; }
    public void setHeaderValue(String headerValue) { this.headerValue = headerValue; }
}
