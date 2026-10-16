# Multi-stage Dockerfile for AuthMatrix (Java backend + Node web frontend)
FROM maven:3.9.9-eclipse-temurin-21 AS backend-builder
WORKDIR /build

COPY pom.xml .
COPY shared/pom.xml shared/
COPY server/pom.xml server/
COPY cli/pom.xml cli/

# Copy sources and package
COPY shared/src shared/src
COPY server/src server/src
COPY cli/src cli/src

RUN mvn -B clean package -DskipTests

# Stage 2: Web frontend builder
FROM node:20-alpine AS web-builder
WORKDIR /web
COPY apps/web/package.json ./
RUN npm install
COPY apps/web/ ./
RUN npm run build

# Stage 3: Runtime container
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

RUN mkdir -p /app/data

# Copy artifacts
COPY --from=backend-builder /build/server/target/authmatrix-server-0.1.0-SNAPSHOT.jar /app/server.jar
COPY --from=backend-builder /build/cli/target/authmatrix-cli-0.1.0-SNAPSHOT.jar /app/cli.jar
COPY --from=web-builder /web/dist /app/static

ENV DB_PATH=/app/data/authmatrix.db \
    API_PORT=4000 \
    PROXY_PORT=8080 \
    TARGET_HOST=http://localhost:3000

EXPOSE 4000 8080 5173

VOLUME ["/app/data"]

ENTRYPOINT ["java", "-jar", "/app/server.jar"]
