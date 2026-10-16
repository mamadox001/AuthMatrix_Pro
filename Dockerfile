# Multi-stage Dockerfile for AuthMatrix Pro (Pure Java Monorepo)

# Stage 1: Build the Maven monorepo
FROM maven:3.9.9-eclipse-temurin-21 AS builder
WORKDIR /build

# Copy root and module POMs
COPY pom.xml .
COPY shared/pom.xml shared/
COPY server/pom.xml server/
COPY cli/pom.xml cli/

# Copy sources (includes embedded web frontend in server/src/main/resources/static)
COPY shared/src shared/src
COPY server/src server/src
COPY cli/src cli/src

# Package all JARs (server JAR automatically embeds the static web UI)
RUN mvn -B clean package -DskipTests

# Stage 2: Minimal, production-ready runtime container
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

RUN mkdir -p /app/data

# Copy packaged JAR artifacts
COPY --from=builder /build/server/target/authmatrix-server-0.1.0-SNAPSHOT.jar /app/server.jar
COPY --from=builder /build/cli/target/authmatrix-cli-0.1.0-SNAPSHOT.jar /app/cli.jar

# Environment defaults
ENV DB_PATH=/app/data/authmatrix.db \
    API_PORT=4000 \
    PROXY_PORT=8080 \
    TARGET_HOST=http://host.docker.internal:3000

# Port 4000: Web UI & REST/WebSocket API
# Port 8080: Reverse Proxy Engine
EXPOSE 4000 8080

VOLUME ["/app/data"]

ENTRYPOINT ["java", "-jar", "/app/server.jar"]
