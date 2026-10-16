package com.authmatrix.shared.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class PolicyAssertion {

    @JsonProperty("body_must_contain")
    private List<String> bodyMustContain = new ArrayList<>();

    @JsonProperty("body_must_not_contain")
    private List<String> bodyMustNotContain = new ArrayList<>();

    @JsonProperty("regex_pattern")
    private String regexPattern;

    @JsonProperty("regex_must_not_match")
    private String regexMustNotMatch;

    @JsonProperty("json_path_equals")
    private Map<String, String> jsonPathEquals = new HashMap<>();

    public PolicyAssertion() {}

    public PolicyAssertion(List<String> bodyMustContain, List<String> bodyMustNotContain,
                           String regexPattern, String regexMustNotMatch,
                           Map<String, String> jsonPathEquals) {
        this.bodyMustContain = bodyMustContain != null ? bodyMustContain : new ArrayList<>();
        this.bodyMustNotContain = bodyMustNotContain != null ? bodyMustNotContain : new ArrayList<>();
        this.regexPattern = regexPattern;
        this.regexMustNotMatch = regexMustNotMatch;
        this.jsonPathEquals = jsonPathEquals != null ? jsonPathEquals : new HashMap<>();
    }

    public List<String> getBodyMustContain() { return bodyMustContain; }
    public void setBodyMustContain(List<String> bodyMustContain) { this.bodyMustContain = bodyMustContain != null ? bodyMustContain : new ArrayList<>(); }

    public List<String> getBodyMustNotContain() { return bodyMustNotContain; }
    public void setBodyMustNotContain(List<String> bodyMustNotContain) { this.bodyMustNotContain = bodyMustNotContain != null ? bodyMustNotContain : new ArrayList<>(); }

    public String getRegexPattern() { return regexPattern; }
    public void setRegexPattern(String regexPattern) { this.regexPattern = regexPattern; }

    public String getRegexMustNotMatch() { return regexMustNotMatch; }
    public void setRegexMustNotMatch(String regexMustNotMatch) { this.regexMustNotMatch = regexMustNotMatch; }

    public Map<String, String> getJsonPathEquals() { return jsonPathEquals; }
    public void setJsonPathEquals(Map<String, String> jsonPathEquals) { this.jsonPathEquals = jsonPathEquals != null ? jsonPathEquals : new HashMap<>(); }

    public boolean hasAssertions() {
        return (bodyMustContain != null && !bodyMustContain.isEmpty()) ||
               (bodyMustNotContain != null && !bodyMustNotContain.isEmpty()) ||
               (regexPattern != null && !regexPattern.isBlank()) ||
               (regexMustNotMatch != null && !regexMustNotMatch.isBlank()) ||
               (jsonPathEquals != null && !jsonPathEquals.isEmpty());
    }
}
