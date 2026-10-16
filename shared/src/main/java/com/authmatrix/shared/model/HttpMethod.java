package com.authmatrix.shared.model;

public enum HttpMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    OPTIONS,
    HEAD;

    public static HttpMethod fromString(String method) {
        if (method == null) return GET;
        return valueOf(method.trim().toUpperCase());
    }
}
