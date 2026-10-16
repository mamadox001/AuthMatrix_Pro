package com.authmatrix.shared.util;

import com.authmatrix.shared.model.AuthMatrixYaml;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class JsonUtils {

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(
            new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
    )
            .registerModule(new JavaTimeModule())
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public static ObjectMapper getJsonMapper() {
        return JSON_MAPPER;
    }

    public static ObjectMapper getYamlMapper() {
        return YAML_MAPPER;
    }

    public static String toJson(Object obj) {
        try {
            return JSON_MAPPER.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize to JSON: " + e.getMessage(), e);
        }
    }

    public static String toPrettyJson(Object obj) {
        try {
            return JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to pretty serialize to JSON: " + e.getMessage(), e);
        }
    }

    public static <T> T fromJson(String json, Class<T> clazz) {
        try {
            return JSON_MAPPER.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to parse JSON: " + e.getMessage(), e);
        }
    }

    public static String toYaml(Object obj) {
        try {
            return YAML_MAPPER.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize to YAML: " + e.getMessage(), e);
        }
    }

    public static AuthMatrixYaml fromYaml(String yaml) {
        try {
            return YAML_MAPPER.readValue(yaml, AuthMatrixYaml.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to parse YAML: " + e.getMessage(), e);
        }
    }
}
