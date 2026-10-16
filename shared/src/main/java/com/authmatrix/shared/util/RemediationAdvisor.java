package com.authmatrix.shared.util;

import com.authmatrix.shared.model.EndpointPolicy;
import com.authmatrix.shared.model.Verdict;

import java.util.LinkedHashMap;
import java.util.Map;

public class RemediationAdvisor {

    public static Map<String, String> generateRemediation(Verdict verdict, EndpointPolicy endpoint, String roleName, int expected, int actual) {
        Map<String, String> fixes = new LinkedHashMap<>();
        String path = endpoint != null ? endpoint.getPath() : "/resource";
        String method = endpoint != null ? endpoint.getMethod().name() : "GET";

        if (verdict == Verdict.BOLA_IDOR_VULNERABILITY) {
            fixes.put("title", "CWE-639 / OWASP API1:2023 - Broken Object Level Authorization (BOLA/IDOR)");
            fixes.put("severity", "CRITICAL");
            fixes.put("explanation", "The application allows role '" + roleName + "' to access resources belonging to a different tenant/user without validating object ownership.");

            fixes.put("spring_boot", """
                // Spring Boot 3 / Java: Validate tenant/user ownership in service or controller
                @PreAuthorize("@tenantSecurity.isOwner(authentication, #tenantId)")
                @GetMapping("%s")
                public ResponseEntity<?> getResource(@PathVariable("tenantId") String tenantId) {
                    return ResponseEntity.ok(service.getByIdAndTenant(id, tenantId));
                }
                """.formatted(path));

            fixes.put("express_js", """
                // Node.js / Express: Middleware checking authenticated user against resource tenant
                app.%s('%s', authenticateToken, (req, res, next) => {
                  if (req.user.tenantId !== req.params.tenantId && req.user.role !== 'admin') {
                    return res.status(403).json({ error: 'Access denied: Object belongs to another tenant' });
                  }
                  next();
                }, handler);
                """.formatted(method.toLowerCase(), path));

            fixes.put("fastapi", """
                # Python / FastAPI: Dependency enforcing tenant isolation
                def verify_tenant_access(tenant_id: str, current_user: User = Depends(get_current_user)):
                    if current_user.tenant_id != tenant_id and "admin" not in current_user.roles:
                        raise HTTPException(status_code=403, detail="Forbidden: Cross-tenant access denied")
                    return current_user
                """);

            fixes.put("golang", """
                // Go / Chi / Gin: Validate token claims against route parameters
                if claims.TenantID != routeParamTenantID && !claims.IsAdmin {
                    w.WriteHeader(http.StatusForbidden)
                    json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized cross-tenant access"})
                    return
                }
                """);
        } else if (verdict == Verdict.REGRESSION_UNAUTHORIZED_ACCESS) {
            fixes.put("title", "CWE-285 / OWASP API5:2023 - Broken Function Level Authorization (BFLA)");
            fixes.put("severity", "HIGH");
            fixes.put("explanation", "Endpoint returned " + actual + " OK when role '" + roleName + "' was expected to be denied (" + expected + "). Role-based access control was bypassed.");

            fixes.put("spring_boot", """
                // Spring Security 6: Restrict endpoint to authorized roles
                @Bean
                public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                    http.authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.%s, "%s").hasRole("ADMIN")
                        .anyRequest().authenticated()
                    );
                    return http.build();
                }
                """.formatted(method, path));

            fixes.put("express_js", """
                // Express: Role authorization guard
                function requireRole(allowedRoles) {
                  return (req, res, next) => {
                    if (!req.user || !allowedRoles.includes(req.user.role)) {
                      return res.status(403).json({ error: 'Forbidden: Insufficient privileges' });
                    }
                    next();
                  };
                }
                router.%s('%s', authenticateToken, requireRole(['ADMIN']), handler);
                """.formatted(method.toLowerCase(), path));

            fixes.put("fastapi", """
                # FastAPI: Role requirement dependency
                def require_admin(current_user: User = Depends(get_current_user)):
                    if current_user.role != "admin":
                        raise HTTPException(status_code=403, detail="Admin role required")
                    return current_user
                """);

            fixes.put("golang", """
                // Go: Require specific role in middleware
                func RequireRole(role string) gin.HandlerFunc {
                    return func(c *gin.Context) {
                        userRole := c.GetString("user_role")
                        if userRole != role {
                            c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden"})
                            return
                        }
                        c.Next()
                    }
                }
                """);
        } else if (verdict == Verdict.REGRESSION_DATA_LEAKAGE) {
            fixes.put("title", "CWE-200 / OWASP API3:2023 - Broken Object Property Level Authorization / Data Leakage");
            fixes.put("severity", "HIGH");
            fixes.put("explanation", "The endpoint returned sensitive fields or unauthorized data that violated policy assertions for role '" + roleName + "'.");

            fixes.put("spring_boot", """
                // Spring: Use Jackson JSON Views or DTO projection to filter sensitive fields
                @JsonView(Views.Public.class)
                @GetMapping("%s")
                public UserProfileDto getProfile() {
                    return service.getProfile();
                }
                """.formatted(path));

            fixes.put("express_js", """
                // Express: Explicit DTO sanitization before sending response
                const sanitizeUser = (user) => {
                  const { passwordHash, ssn, billingInfo, ...safeData } = user;
                  return safeData;
                };
                res.json(sanitizeUser(profile));
                """);

            fixes.put("fastapi", """
                # FastAPI: Pydantic response_model filtering
                @router.get("%s", response_model=PublicUserResponse)
                def get_profile():
                    return user_service.get_user()
                """.formatted(path));

            fixes.put("golang", """
                // Go: Return sanitized public DTO struct
                type PublicResponse struct {
                    Username string `json:"username"`
                    Role     string `json:"role"`
                }
                """);
        } else if (verdict == Verdict.ASSERTION_FAILED) {
            fixes.put("title", "Semantic Authorization Assertion Failed");
            fixes.put("severity", "MEDIUM");
            fixes.put("explanation", "The response status was expected, but response body assertions (regex, JSONPath, or required/forbidden strings) failed.");
            fixes.put("recommendation", "Review the endpoint response schema and ensure error payloads or tenant tokens match required contract specifications.");
        }

        return fixes;
    }
}
