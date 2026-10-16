package com.authmatrix.shared.util;

import com.authmatrix.shared.model.CreateEndpointPolicyInput;
import com.authmatrix.shared.model.HttpMethod;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OpenApiImporterTest {

    @Test
    void shouldParseOpenApi3JsonSpecCorrectly() {
        String jsonSpec = """
            {
              "openapi": "3.0.1",
              "info": {
                "title": "Customer Invoicing API",
                "version": "1.0.0"
              },
              "servers": [
                { "url": "https://api.example.com/v1" }
              ],
              "paths": {
                "/invoices/{invoiceId}": {
                  "get": {
                    "summary": "Retrieve invoice by ID",
                    "parameters": [
                      { "name": "invoiceId", "in": "path", "required": true }
                    ]
                  },
                  "delete": {
                    "summary": "Delete invoice by ID"
                  }
                },
                "/admin/audit-logs": {
                  "post": {
                    "summary": "Create audit log entry",
                    "requestBody": {
                      "content": {
                        "application/json": {
                          "schema": {
                            "type": "object",
                            "properties": {
                              "action": { "type": "string" },
                              "severity": { "type": "integer" }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            """;

        OpenApiImporter.ImportResult result = OpenApiImporter.parseSpec(jsonSpec, List.of("admin", "member", "guest"));

        assertThat(result.specVersion()).isEqualTo("OpenAPI 3.0.1");
        assertThat(result.title()).isEqualTo("Customer Invoicing API");
        assertThat(result.detectedTargetBaseUrl()).isEqualTo("https://api.example.com/v1");
        assertThat(result.endpoints()).hasSize(3);

        CreateEndpointPolicyInput getInvoice = result.endpoints().stream()
                .filter(e -> e.getMethod() == HttpMethod.GET)
                .findFirst()
                .orElseThrow();

        assertThat(getInvoice.getPath()).isEqualTo("/invoices/{invoiceId}");
        assertThat(getInvoice.getName()).contains("Retrieve invoice by ID");
        assertThat(getInvoice.getExpect().get("admin")).isEqualTo(200);
        assertThat(getInvoice.getExpect().get("guest")).isEqualTo(401);

        CreateEndpointPolicyInput auditPost = result.endpoints().stream()
                .filter(e -> e.getMethod() == HttpMethod.POST)
                .findFirst()
                .orElseThrow();

        assertThat(auditPost.getPath()).isEqualTo("/admin/audit-logs");
        assertThat(auditPost.getBody()).contains("action").contains("severity");
        assertThat(auditPost.getExpect().get("member")).isEqualTo(403); // admin only
        assertThat(auditPost.getExpect().get("admin")).isEqualTo(201);
    }

    @Test
    void shouldParseSwagger2YamlSpecCorrectly() {
        String yamlSpec = """
            swagger: "2.0"
            info:
              title: "Payment Gateway Service"
              version: "2.0.0"
            host: "payment.internal"
            basePath: "/api"
            schemes:
              - "https"
            paths:
              /public/health:
                get:
                  summary: "Service Health"
              /payments/charge:
                post:
                  summary: "Process credit card charge"
            """;

        OpenApiImporter.ImportResult result = OpenApiImporter.parseSpec(yamlSpec, List.of("admin", "guest"));

        assertThat(result.specVersion()).isEqualTo("Swagger 2.0");
        assertThat(result.detectedTargetBaseUrl()).isEqualTo("https://payment.internal/api");
        assertThat(result.endpoints()).hasSize(2);

        CreateEndpointPolicyInput health = result.endpoints().stream()
                .filter(e -> e.getPath().equals("/public/health"))
                .findFirst()
                .orElseThrow();

        assertThat(health.getExpect().get("guest")).isEqualTo(200); // Public endpoint
    }
}
