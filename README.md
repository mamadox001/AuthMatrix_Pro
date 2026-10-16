# AuthMatrix Pro 🛡️

> Local-first HTTP API debugging reverse proxy and declarative Role-Based Access Control (RBAC) contract verification platform built entirely with **Java 21+**, **Spring Boot 3**, and **SQLite (WAL mode)**, featuring an integrated security testing suite.

---

## 🌟 Overview & Architecture

AuthMatrix provides penetration testers, security engineers, and backend architects with complete visibility and confidence in API authorization boundaries:

1. **Debugging Reverse Proxy (`:8080`):** Intercepts HTTP traffic targeting upstream services, normalizes headers (`Accept-Encoding: identity`) for readable UTF-8 payloads, and streams traffic in real-time over WebSockets (`/ws/traffic`).
2. **Integrated Security Tool Suite (`:4000`):**
   - **Target / Site Map:** Discovers endpoints, paths, and hierarchical site maps from live proxy traffic.
   - **Proxy & Intercept:** Live intercept toggle with Raw (editable), Headers table, Query/Body parameters, and Hex dump views.
   - **HTTP History:** High-density data grid with sortable columns (`#`, `Method`, `URL`, `Status`, `Length`, `Time`, `Timestamp`), quick filters, and one-click actions (*Send to Repeater*, *Create Policy*, *Copy as cURL*).
   - **Repeater:** Multi-tabbed HTTP request crafter with key-value headers editor, body editor, latency & payload size badges, and comprehensive response inspectors (Pretty JSON/HTML, Raw, Headers, Hex dump, and sandboxed HTML iframe Render preview).
   - **AuthMatrix Verifier:** Automated 2D contract verification engine testing all Roles × Endpoints. Detects **Critical BOLA / IDOR / Privilege Escalations** (`REGRESSION_UNAUTHORIZED_ACCESS`), status mismatches, and network errors. Features a slide-out cell finding inspection drawer with detailed exploit reproduction.
   - **Decoder:** Security transformation tool supporting URL Encode/Decode, Base64 Encode/Decode, Hex Encode/Decode, HTML Entities, cryptographic hashes (MD5, SHA-1, SHA-256), and JWT Token Claim Inspector.
   - **Comparer:** Visual word-by-word and line-by-line diff engine to compare baseline responses vs test responses side-by-side.
   - **Roles & Policies:** Identity credential vault and declarative contract rules.
3. **Local-First & Zero-Config Database:** Embedded SQLite (`authmatrix.db`) operating in **WAL (Write-Ahead Logging)** mode. Zero external database setup, migrations, or cloud dependencies—the database auto-creates, migrates schemas, and seeds default roles on first launch.
4. **Headless CI/CD CLI:** Standalone CLI (`authmatrix-cli.jar`) executing contract verification in GitHub Actions or GitLab CI pipelines with exit code enforcement.

---

## 🏗️ Architecture

```text
┌─────────────────────────┐       HTTP Requests (:8080)       ┌────────────────────────┐
│  Client / Apps / cURL   │ ─────────────────────────────────▶│ AuthMatrix Proxy Engine│
└─────────────────────────┘                                   └───────────┬────────────┘
                                                                          │ (Captures UTF-8 traffic)
                                                                          ▼
┌─────────────────────────┐       WebSocket (:4000)           ┌────────────────────────┐
│  AuthMatrix Pro Web UI  │◀──────────────────────────────────│  Spring Boot REST/WS   │
│ (Target, Proxy, Matrix, │                                   └───────────┬────────────┘
│  Repeater, Decoder, etc)│                                               │
└─────────────────────────┘                                               ▼
                                                              ┌────────────────────────┐
┌─────────────────────────┐       Matrix Contract Checks      │ SQLite DB (WAL Mode)   │
│ CI/CD Pipeline (Picocli)│ ─────────────────────────────────▶│   (authmatrix.db)      │
└─────────────────────────┘                                   └────────────────────────┘
```

### Modules
- **`shared`**: Domain models (`Role`, `EndpointPolicy`, `TrafficLog`, `MatrixResult`, `AuthMatrixYaml`, `Verdict`), Jackson serialization, and validation.
- **`server`**: Spring Boot backend hosting REST endpoints (`:4000`), WebSocket traffic broadcasting (`/ws/traffic`), SQLite persistence with WAL mode, embedded AuthMatrix web application, and high-performance reverse proxy (`:8080`).
- **`cli`**: Picocli CLI runner for headless contract verification with ASCII table formatting and exit code checks.

---

## 🚀 Quickstart

### Prerequisites
- **Java 21+** (`java -version`)
- **Maven 3.9+** (`mvn -version`)

*(No Node.js or npm required — the web app is embedded directly inside the Java server JAR!)*

### 1. Build the Monorepo

```bash
mvn clean package -DskipTests
```

This compiles all modules and packages:
- `server/target/authmatrix-server-0.1.0-SNAPSHOT.jar`
- `cli/target/authmatrix-cli-0.1.0-SNAPSHOT.jar`
- `shared/target/authmatrix-shared-0.1.0-SNAPSHOT.jar`

### 2. Start AuthMatrix Server & Proxy

```bash
java -jar server/target/authmatrix-server-0.1.0-SNAPSHOT.jar
```

Default listening ports:
- **AuthMatrix Web UI & REST/WS API:** `http://localhost:4000`
- **Reverse Proxy:** `http://localhost:8080` (forwards to `http://localhost:3000` by default)

Custom configuration via environment variables:
```bash
TARGET_HOST=http://localhost:5000 API_PORT=4000 PROXY_PORT=8080 DB_PATH=authmatrix.db java -jar server/target/authmatrix-server-0.1.0-SNAPSHOT.jar
```

Open `http://localhost:4000` in your browser to launch the AuthMatrix Web UI.

### 💾 Zero-Config Embedded Database (No Setup Required)

AuthMatrix requires **no database installation, setup, or external services**:
- **Automatic Initialization:** An embedded SQLite database (`authmatrix.db`) is automatically created in the working directory on first launch.
- **Auto Schema & Seeding:** All required tables (`traffic_logs`, `auth_roles`, `endpoint_policies`, `matrix_results`) and default starter security roles (`admin`, `member_a`, `guest`) are initialized automatically.
- **WAL Mode (Write-Ahead Logging):** Configured for high-throughput concurrent reads and writes with zero lock contention.
- **100% Local & Private:** All intercepted request bodies, headers, and exploit reproduction details stay strictly on your local machine.
- *(Optional)* To customize the database file location, pass the `DB_PATH` environment variable:
  ```bash
  DB_PATH=/custom/path/my_authmatrix.db java -jar server/target/authmatrix-server-0.1.0-SNAPSHOT.jar
  ```

---

## 🧪 Headless CI/CD Verification

Verify your RBAC contracts locally or in automated deployment pipelines:

```bash
java -jar cli/target/authmatrix-cli-0.1.0-SNAPSHOT.jar verify .authmatrix.yaml.example
```

### Command Options

```text
Usage: authmatrix verify [-hV] [--fail-on-regression] [--json]
                         [--timeout=<timeoutMs>] [<configPath>]

Arguments:
  [<configPath>]       Path to the .authmatrix.yaml file (default: .authmatrix.yaml)

Options:
      --fail-on-regression
                       Exit with non-zero status code if any RBAC regression or status mismatch occurs
      --timeout=<timeoutMs>
                       Per-request timeout in milliseconds (default: 10000)
      --json           Output results in machine-readable JSON format
  -h, --help           Show this help message and exit.
  -V, --version        Print version information and exit.
```

---

## 📋 Example Contract (`.authmatrix.yaml`)

```yaml
version: "1.0"
target_base_url: "http://localhost:3000"

roles:
  admin:
    header_name: "Authorization"
    header_value: "Bearer ${ADMIN_TOKEN:-admin-secret}"
  member_a:
    header_name: "Authorization"
    header_value: "Bearer ${MEMBER_A_TOKEN:-member-a-token}"
  guest:
    header_name: "Authorization"
    header_value: ""

endpoints:
  - name: "List Users"
    method: "GET"
    path: "/api/users"
    expect:
      admin: 200
      member_a: 200
      guest: 401

  - name: "Delete User"
    method: "DELETE"
    path: "/api/users/123"
    expect:
      admin: 204
      member_a: 403
      guest: 401
```

---

## 🐳 Docker Deployment

Run the complete suite via Docker Compose:

```bash
docker compose up --build
```

---

## 📜 License

Apache 2.0. Open-source for personal and enterprise security testing.
