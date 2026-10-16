package com.authmatrix.shared.util;

import com.authmatrix.shared.model.CreateEndpointPolicyInput;
import com.authmatrix.shared.model.HttpMethod;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class OpenApiImporter {

    public record ImportResult(
            String detectedTargetBaseUrl,
            List<CreateEndpointPolicyInput> endpoints,
            int endpointsCount,
            String specVersion,
            String title
    ) {}

    public static ImportResult parseSpec(String specContent, List<String> availableRoleNames) {
        if (specContent == null || specContent.isBlank()) {
            throw new IllegalArgumentException("Specification content cannot be empty");
        }

        JsonNode root;
        try {
            if (specContent.trim().startsWith("{")) {
                root = JsonUtils.getJsonMapper().readTree(specContent);
            } else {
                root = JsonUtils.getYamlMapper().readTree(specContent);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse OpenAPI/Swagger content: " + e.getMessage(), e);
        }

        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("Invalid specification format: root must be a JSON/YAML object");
        }

        String specVersion = "Unknown";
        if (root.has("openapi")) {
            specVersion = "OpenAPI " + root.get("openapi").asText();
        } else if (root.has("swagger")) {
            specVersion = "Swagger " + root.get("swagger").asText();
        }

        String title = "API Specification";
        if (root.has("info") && root.get("info").has("title")) {
            title = root.get("info").get("title").asText();
        }

        // Detect base URL
        String targetBaseUrl = null;
        if (root.has("servers") && root.get("servers").isArray() && !root.get("servers").isEmpty()) {
            JsonNode firstServer = root.get("servers").get(0);
            if (firstServer.has("url")) {
                targetBaseUrl = firstServer.get("url").asText();
            }
        } else if (root.has("host")) {
            String host = root.get("host").asText();
            String scheme = "http";
            if (root.has("schemes") && root.get("schemes").isArray() && !root.get("schemes").isEmpty()) {
                scheme = root.get("schemes").get(0).asText();
            }
            String basePath = root.has("basePath") ? root.get("basePath").asText() : "";
            targetBaseUrl = scheme + "://" + host + basePath;
        }

        List<String> roles = (availableRoleNames != null && !availableRoleNames.isEmpty())
                ? availableRoleNames
                : List.of("admin", "member", "guest");

        List<CreateEndpointPolicyInput> endpoints = new ArrayList<>();
        JsonNode pathsNode = root.get("paths");

        if (pathsNode != null && pathsNode.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = pathsNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> pathEntry = fields.next();
                String path = pathEntry.getKey();
                JsonNode pathItem = pathEntry.getValue();

                if (!pathItem.isObject()) continue;

                // Check operations
                for (String methodKey : List.of("get", "post", "put", "delete", "patch", "options", "head")) {
                    if (pathItem.has(methodKey)) {
                        JsonNode opNode = pathItem.get(methodKey);
                        HttpMethod httpMethod = HttpMethod.fromString(methodKey.toUpperCase());

                        String summary = null;
                        if (opNode.has("summary") && !opNode.get("summary").asText().isBlank()) {
                            summary = opNode.get("summary").asText();
                        } else if (opNode.has("operationId") && !opNode.get("operationId").asText().isBlank()) {
                            summary = opNode.get("operationId").asText();
                        }

                        String policyName = summary != null
                                ? "[" + httpMethod.name() + "] " + summary
                                : "[" + httpMethod.name() + "] " + path;

                        Map<String, String> headers = new LinkedHashMap<>();
                        headers.put("Accept", "application/json");

                        // Extract parameters
                        List<JsonNode> paramNodes = new ArrayList<>();
                        if (pathItem.has("parameters") && pathItem.get("parameters").isArray()) {
                            for (JsonNode p : pathItem.get("parameters")) paramNodes.add(p);
                        }
                        if (opNode.has("parameters") && opNode.get("parameters").isArray()) {
                            for (JsonNode p : opNode.get("parameters")) paramNodes.add(p);
                        }

                        String sampleBody = null;
                        for (JsonNode param : paramNodes) {
                            String in = param.has("in") ? param.get("in").asText() : "";
                            String pName = param.has("name") ? param.get("name").asText() : "";
                            if ("header".equalsIgnoreCase(in) && !pName.equalsIgnoreCase("Authorization")) {
                                String example = param.has("example") ? param.get("example").asText() : "test-value";
                                headers.put(pName, example);
                            } else if ("body".equalsIgnoreCase(in)) {
                                // Swagger 2.0 body param
                                sampleBody = generateSampleFromSchema(param.get("schema"));
                            }
                        }

                        // OpenAPI 3.x requestBody
                        if (sampleBody == null && opNode.has("requestBody")) {
                            JsonNode reqBodyNode = opNode.get("requestBody");
                            if (reqBodyNode.has("content")) {
                                JsonNode contentNode = reqBodyNode.get("content");
                                if (contentNode.has("application/json")) {
                                    JsonNode jsonContent = contentNode.get("application/json");
                                    if (jsonContent.has("example")) {
                                        sampleBody = JsonUtils.toJson(jsonContent.get("example"));
                                    } else if (jsonContent.has("schema")) {
                                        sampleBody = generateSampleFromSchema(jsonContent.get("schema"));
                                    }
                                }
                            }
                        }

                        if (sampleBody != null && !sampleBody.isBlank()) {
                            headers.put("Content-Type", "application/json");
                        }

                        // Determine default expectations
                        Map<String, Integer> expect = new LinkedHashMap<>();
                        boolean isPublic = path.toLowerCase().contains("public") ||
                                          path.toLowerCase().contains("health") ||
                                          path.toLowerCase().contains("login") ||
                                          path.toLowerCase().contains("ping");

                        boolean isAdminOnly = path.toLowerCase().contains("admin") ||
                                              path.toLowerCase().contains("manage") ||
                                              path.toLowerCase().contains("audit") ||
                                              path.toLowerCase().contains("billing");

                        int successCode = httpMethod == HttpMethod.POST ? 201 : 200;

                        for (String role : roles) {
                            String rLower = role.toLowerCase();
                            if (isPublic) {
                                expect.put(role, 200);
                            } else if (rLower.contains("admin") || rLower.equals("root") || rLower.equals("super")) {
                                expect.put(role, successCode);
                            } else if (rLower.contains("guest") || rLower.contains("anon") || rLower.contains("public")) {
                                expect.put(role, 401);
                            } else {
                                // Standard member/user
                                if (isAdminOnly) {
                                    expect.put(role, 403);
                                } else {
                                    expect.put(role, successCode);
                                }
                            }
                        }

                        endpoints.add(new CreateEndpointPolicyInput(
                                policyName,
                                httpMethod,
                                path,
                                headers,
                                sampleBody,
                                expect
                        ));
                    }
                }
            }
        }

        return new ImportResult(targetBaseUrl, endpoints, endpoints.size(), specVersion, title);
    }

    private static String generateSampleFromSchema(JsonNode schema) {
        if (schema == null) return "{}";
        try {
            Map<String, Object> sample = generateObjectSample(schema);
            return JsonUtils.toJson(sample);
        } catch (Exception e) {
            return "{}";
        }
    }

    private static Map<String, Object> generateObjectSample(JsonNode schema) {
        Map<String, Object> map = new LinkedHashMap<>();
        if (schema.has("properties") && schema.get("properties").isObject()) {
            Iterator<Map.Entry<String, JsonNode>> props = schema.get("properties").fields();
            while (props.hasNext()) {
                Map.Entry<String, JsonNode> prop = props.next();
                String propName = prop.getKey();
                JsonNode propSchema = prop.getValue();
                map.put(propName, generateValueSample(propSchema, propName));
            }
        }
        return map;
    }

    private static Object generateValueSample(JsonNode node, String name) {
        if (node.has("example")) {
            JsonNode ex = node.get("example");
            if (ex.isTextual()) return ex.asText();
            if (ex.isNumber()) return ex.numberValue();
            if (ex.isBoolean()) return ex.asBoolean();
        }

        String type = node.has("type") ? node.get("type").asText().toLowerCase() : "string";
        String format = node.has("format") ? node.get("format").asText().toLowerCase() : "";

        return switch (type) {
            case "integer", "int" -> 1;
            case "number", "float", "double" -> 99.99;
            case "boolean" -> true;
            case "array" -> List.of("item-1");
            case "object" -> Map.of("key", "value");
            default -> {
                if ("email".equals(format) || name.toLowerCase().contains("email")) yield "user@example.com";
                if ("uuid".equals(format) || name.toLowerCase().contains("id")) yield UUID.randomUUID().toString();
                if ("date".equals(format)) yield "2026-01-01";
                if ("date-time".equals(format)) yield "2026-01-01T00:00:00Z";
                yield name + "_value";
            }
        };
    }
}
