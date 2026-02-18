# GAE-GNP Facultativo — Python/Flask Rewrite

Rewrite of the Java-based microservice platform for GNP reinsurance operations.

The original GAE-GNP Facultativo system consisted of six Java microservice modules
(**administrador**, **catalogos**, **procesos**, **reportes**,
**sincronizador-archivos**, **tarifas**) built on Spring Framework, Spring Security,
embedded Apache Tomcat, and gRPC-Netty, deployed on Google Cloud Platform with an
Apigee API Gateway. This project rewrites the entire platform as a unified
**Python 3 / Flask** application, preserving every service endpoint and business-logic
pathway while organizing the six modules as Flask blueprints to maintain domain
separation.

**Technology Stack:**

| Component | Technology | Version |
|---|---|---|
| Language | Python | 3.13+ |
| Web Framework | Flask | 3.1.2 |
| gRPC | grpcio / grpcio-tools | 1.78.0 |
| WSGI Server | Gunicorn | 25.1.0 |
| Config Parsing | PyYAML | 6.0.3 |
| Input Sanitization | bleach | 6.2.0 |
| Serialization | protobuf | 6.33.5 |
| Environment Loader | python-dotenv | 1.1.0 |
| GCP Secrets | google-cloud-secret-manager | 2.26.0 |

---

## Architecture Overview

The application runs a **dual-server architecture**:

1. **Flask WSGI Server (Gunicorn)** — serves HTTP/HTTPS REST endpoints for
   external-facing modules, fronted by the Apigee API Gateway.
2. **gRPC Server (grpcio)** — serves inter-service RPC calls for all six modules,
   running concurrently alongside the WSGI server in a background thread.

### External-Facing Modules (HTTP via Apigee API Gateway)

| Module | Blueprint | URL Prefix | Description |
|---|---|---|---|
| Module 1 — administrador | `administrador_bp` | `/api/administrador` | User authentication, role management, user administration |
| Module 3 — procesos | `procesos_bp` | `/api/procesos` | Offer management and policy processing |
| Module 5 — sincronizador_archivos | `sincronizador_archivos_bp` | `/api/sincronizador-archivos` | Configuration-driven file synchronization |

### Internal gRPC-Only Modules

| Module | Servicer | Description |
|---|---|---|
| Module 2 — catalogos | `CatalogosServicer` | Reinsurer catalog management |
| Module 4 — reportes | `ReportesServicer` | User file and report generation |
| Module 6 — tarifas | `TarifasServicer` | Tariff calculation and rate management |

### Authentication

External requests pass through the **Apigee API Gateway**, which appends a
gateway-level token. The Flask application validates this token via a
`before_request` middleware hook applied to external-facing blueprints. Endpoint-level
authorization is enforced through `@require_auth` and `@require_role` decorators that
implement role-based access control (RBAC), replacing the original Spring Security
filter chain.

### Configuration

Configuration follows a layered hierarchy:

```
base config (config/application.yml)
  → environment-specific overrides (config/application-{env}.yml)
    → environment variables (os.environ / .env file)
      → GCP Secret Manager (for sensitive credentials)
```

---

## Module Descriptions

### administrador (Module 1)

Handles user authentication, role management, and user administration. Exposes HTTP
endpoints through the Apigee API Gateway.

| Service | Responsibility |
|---|---|
| `LoginService` | User login, logout, and token refresh |
| `RolService` | Role creation, assignment, and permission management |
| `UsuarioService` | User CRUD operations and profile management |

### catalogos (Module 2)

Manages the reinsurer catalog. Accessible only via gRPC — consumed primarily by
Module 3 (procesos) during offer processing.

| Service | Responsibility |
|---|---|
| `ReaseguradoraService` | Reinsurer catalog lookup, creation, and updates |

### procesos (Module 3)

Core business module for offer management and policy processing. Exposes HTTP
endpoints through the Apigee API Gateway. Makes gRPC calls to Module 2 (catalogos)
for catalog lookups and to Module 6 (tarifas) for tariff calculations.

| Service | Responsibility |
|---|---|
| `OfertaService` | Offer creation, evaluation, and lifecycle management |
| `PolizaService` | Policy processing, validation, and state transitions |

### reportes (Module 4)

Manages user file storage and report generation. Accessible only via gRPC — consumed
by Module 1 (administrador) and Module 5 (sincronizador_archivos).

| Service | Responsibility |
|---|---|
| `ArchivosUsuarioService` | User file management and report generation |

### sincronizador_archivos (Module 5)

Handles configuration-driven file synchronization across environments. Exposes HTTP
endpoints through the Apigee API Gateway. Makes gRPC calls to Module 4 (reportes)
for file coordination.

| Service | Responsibility |
|---|---|
| File Sync Services | Bidirectional file synchronization with dual-environment scope |

### tarifas (Module 6)

Provides tariff calculation and rate management. Accessible only via gRPC — consumed
by Module 3 (procesos) during policy evaluation.

| Service | Responsibility |
|---|---|
| Tariff Services | Tariff calculation, rate lookup, and rate management |

---

## Project Structure

```
├── app/
│   ├── __init__.py              # Application factory (create_app)
│   ├── config.py                # Configuration management
│   ├── extensions.py            # Flask extensions and gRPC channel manager
│   ├── logging_config.py        # Structured logging setup
│   ├── auth/
│   │   ├── __init__.py          # Auth package initialization
│   │   ├── middleware.py        # Apigee token validation middleware
│   │   ├── decorators.py       # @require_auth, @require_role decorators
│   │   └── services.py         # Session management and RBAC enforcement
│   ├── blueprints/
│   │   ├── __init__.py          # Blueprint registry
│   │   ├── administrador/       # Module 1 — user auth and admin
│   │   │   ├── __init__.py
│   │   │   ├── routes.py
│   │   │   └── services.py
│   │   ├── catalogos/           # Module 2 — reinsurer catalogs
│   │   │   ├── __init__.py
│   │   │   ├── routes.py
│   │   │   └── services.py
│   │   ├── procesos/            # Module 3 — offers and policies
│   │   │   ├── __init__.py
│   │   │   ├── routes.py
│   │   │   └── services.py
│   │   ├── reportes/            # Module 4 — files and reports
│   │   │   ├── __init__.py
│   │   │   ├── routes.py
│   │   │   └── services.py
│   │   ├── sincronizador_archivos/  # Module 5 — file sync
│   │   │   ├── __init__.py
│   │   │   ├── routes.py
│   │   │   └── services.py
│   │   └── tarifas/             # Module 6 — tariff calculation
│   │       ├── __init__.py
│   │       ├── routes.py
│   │       └── services.py
│   ├── grpc_server/
│   │   ├── __init__.py          # gRPC package initialization
│   │   ├── server.py           # gRPC server setup and lifecycle
│   │   ├── servicers.py        # gRPC servicer implementations
│   │   ├── interceptors.py     # Logging and auth interceptors
│   │   └── clients.py          # gRPC client stub factory
│   └── utils/
│       ├── __init__.py          # Utilities package initialization
│       ├── input_sanitizer.py   # CWE-117 log injection prevention
│       └── validators.py       # Request payload validation
├── protos/
│   ├── common.proto             # Shared message types
│   ├── administrador.proto      # Module 1 gRPC service definitions
│   ├── catalogos.proto          # Module 2 gRPC service definitions
│   ├── procesos.proto           # Module 3 gRPC service definitions
│   ├── reportes.proto           # Module 4 gRPC service definitions
│   ├── sincronizador_archivos.proto  # Module 5 gRPC service definitions
│   └── tarifas.proto            # Module 6 gRPC service definitions
├── config/
│   ├── application.yml          # Base configuration
│   ├── application-test.yml     # Test environment overrides
│   ├── application-prod.yml     # Production environment settings
│   └── logging.yml              # Logging configuration
├── tests/
│   ├── conftest.py              # Shared pytest fixtures
│   ├── unit/
│   │   ├── test_administrador_services.py
│   │   ├── test_catalogos_services.py
│   │   ├── test_procesos_services.py
│   │   ├── test_reportes_services.py
│   │   ├── test_sincronizador_services.py
│   │   ├── test_tarifas_services.py
│   │   ├── test_auth.py
│   │   ├── test_input_sanitizer.py
│   │   └── test_config.py
│   └── integration/
│       ├── test_grpc_communication.py
│       ├── test_api_endpoints.py
│       └── test_apigee_auth.py
├── pyproject.toml               # Project metadata and dependencies
├── requirements.txt             # Pinned production dependencies
├── requirements-dev.txt         # Development and testing dependencies
├── Makefile                     # Build, test, and deploy commands
├── Dockerfile                   # Container build configuration
├── app.yaml                     # Google App Engine deployment descriptor
├── gunicorn.conf.py             # Gunicorn WSGI server configuration
├── .env.example                 # Environment variable template
└── .gitignore                   # Python-specific ignore patterns
```

---

## Prerequisites

- **Python 3.13+** — the application targets the Python 3.13 runtime
- **pip** (latest) — for installing dependencies from PyPI
- **Protocol Buffer compiler (`protoc`)** — required to compile `.proto` files into
  Python stubs; install via `apt install protobuf-compiler` or use the bundled
  compiler from `grpcio-tools` (`python -m grpc_tools.protoc`)
- **GCP SDK** (optional) — required only for deploying to Google App Engine or
  accessing GCP Secret Manager locally

---

## Quick Start

```bash
# Clone the repository
git clone <repo-url>
cd 10feb_55

# Create and activate a virtual environment
python3.13 -m venv .venv
source .venv/bin/activate

# Install production dependencies
pip install -r requirements.txt

# Install development and testing dependencies
pip install -r requirements-dev.txt

# Alternatively, install everything via pyproject.toml (editable mode)
pip install -e ".[dev]"

# Compile Protocol Buffer definitions
make proto-compile

# Configure the environment
cp .env.example .env
# Edit .env with your Apigee token, GCP project ID, and other settings

# Run the development server
make run-dev
```

The development server starts both the Flask WSGI server (default port `8080`) and
the gRPC server (default port `50051`).

---

## Configuration

### Configuration Hierarchy

The application resolves configuration values in the following order (later sources
override earlier ones):

1. **Base configuration** — `config/application.yml` defines default values for all
   settings including server ports, logging levels, and service registry entries.
2. **Environment-specific overrides** — `config/application-test.yml` or
   `config/application-prod.yml` override base values depending on the active
   environment.
3. **Environment variables** — values set in the shell environment or loaded from a
   `.env` file via `python-dotenv` override YAML configuration.
4. **GCP Secret Manager** — when `SECRET_MANAGER_ENABLED=true`, sensitive values
   (such as the Apigee token) are resolved from Google Cloud Secret Manager at
   runtime.

### Required Environment Variables

| Variable | Description | Default |
|---|---|---|
| `FLASK_ENV` | Application environment (`development`, `testing`, `production`) | `development` |
| `FLASK_PORT` | HTTP server listen port | `8080` |
| `GRPC_PORT` | gRPC server listen port | `50051` |
| `APIGEE_TOKEN` | Apigee API Gateway authentication token | *(none — must be set)* |
| `GCP_PROJECT_ID` | Google Cloud Platform project identifier | *(none — required for GCP features)* |
| `SECRET_MANAGER_ENABLED` | Enable GCP Secret Manager integration (`true`/`false`) | `false` |

> **Security Note:** Never commit real tokens or secrets to version control. Use
> `.env` files (which are `.gitignore`d) or GCP Secret Manager for all sensitive
> values.

---

## API Documentation

### External HTTP Endpoints

External clients interact with the application through the **Apigee API Gateway**,
which routes requests to the following Flask blueprint prefixes:

#### Module 1 — administrador (`/api/administrador`)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/administrador/login` | Authenticate a user and obtain a session token |
| `POST` | `/api/administrador/logout` | Invalidate the current session |
| `POST` | `/api/administrador/token/refresh` | Refresh an expiring session token |
| `GET` | `/api/administrador/roles` | List all available roles |
| `POST` | `/api/administrador/roles` | Create a new role |
| `GET` | `/api/administrador/usuarios` | List users |
| `POST` | `/api/administrador/usuarios` | Create a new user |
| `GET` | `/api/administrador/usuarios/<id>` | Retrieve user details |
| `PUT` | `/api/administrador/usuarios/<id>` | Update user information |
| `DELETE` | `/api/administrador/usuarios/<id>` | Remove a user |

#### Module 3 — procesos (`/api/procesos`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/procesos/ofertas` | List offers |
| `POST` | `/api/procesos/ofertas` | Create a new offer |
| `GET` | `/api/procesos/ofertas/<id>` | Retrieve offer details |
| `PUT` | `/api/procesos/ofertas/<id>` | Update an offer |
| `DELETE` | `/api/procesos/ofertas/<id>` | Remove an offer |
| `GET` | `/api/procesos/polizas` | List policies |
| `POST` | `/api/procesos/polizas` | Create a new policy |
| `GET` | `/api/procesos/polizas/<id>` | Retrieve policy details |
| `PUT` | `/api/procesos/polizas/<id>` | Update a policy |
| `DELETE` | `/api/procesos/polizas/<id>` | Remove a policy |

#### Module 5 — sincronizador_archivos (`/api/sincronizador-archivos`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/sincronizador-archivos/status` | Check file synchronization status |
| `POST` | `/api/sincronizador-archivos/sync` | Trigger a file synchronization job |
| `GET` | `/api/sincronizador-archivos/config` | Retrieve sync configuration |
| `PUT` | `/api/sincronizador-archivos/config` | Update sync configuration |

#### Internal gRPC Services

Modules **catalogos** (Module 2), **reportes** (Module 4), and **tarifas**
(Module 6) are not accessible over HTTP. They expose gRPC services only, consumed by
other modules within the application via the gRPC client stub factory.

---

## Testing

The project uses **pytest** as the test framework with **pytest-cov** for coverage
reporting and **pytest-flask** for Flask-specific test fixtures.

```bash
# Run the complete test suite
make test

# Run tests with coverage reporting
pytest --cov=app tests/

# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/

# Run a specific test module
pytest tests/unit/test_administrador_services.py

# Run tests with verbose output
pytest -v --tb=short tests/
```

### Test Organization

- **`tests/conftest.py`** — shared fixtures including the Flask test app, test client,
  gRPC test channel, and mock configuration
- **`tests/unit/`** — unit tests for all service classes, authentication, input
  sanitization, and configuration loading
- **`tests/integration/`** — integration tests for gRPC inter-service communication,
  REST API endpoints, and Apigee token validation flows

### Coverage

The project enforces a minimum coverage threshold of **70%** (configured in
`pyproject.toml`). Coverage reports are generated automatically when running
`make test`.

---

## Deployment

### Google App Engine

Deploy to Google App Engine using the `app.yaml` deployment descriptor:

```bash
# Authenticate with GCP
gcloud auth login
gcloud config set project <your-gcp-project-id>

# Deploy to App Engine
gcloud app deploy app.yaml

# View application logs
gcloud app logs tail -s default
```

The `app.yaml` file specifies the Python 3.13 runtime, instance class, automatic
scaling parameters, and environment variables.

### Docker

Build and run the application as a Docker container:

```bash
# Build the Docker image
docker build -t gae-gnp-facultativo .

# Run the container
docker run -p 8080:8080 -p 50051:50051 --env-file .env gae-gnp-facultativo
```

The `Dockerfile` uses a multi-stage build with a Python 3.13 base image. The
entrypoint starts Gunicorn which manages Flask worker processes while the gRPC server
runs in a background thread.

### Gunicorn (Production)

For direct Gunicorn deployment without Docker:

```bash
# Start the production server
make run-prod

# Or run Gunicorn directly
gunicorn -c gunicorn.conf.py 'app:create_app()'
```

The `gunicorn.conf.py` file configures worker count, bind address, timeouts, and
access logging for production use.

---

## Development

### Makefile Targets

| Target | Description |
|---|---|
| `make install` | Install all dependencies (production and development) |
| `make proto-compile` | Compile `.proto` files into Python stubs using `grpcio-tools` |
| `make test` | Run the full pytest test suite with coverage |
| `make lint` | Run linting checks on the codebase |
| `make run-dev` | Start the Flask development server with hot reload |
| `make run-prod` | Start the Gunicorn production server |
| `make docker-build` | Build the Docker image |

### Coding Conventions

- **Application Factory Pattern** — the Flask application is created via `create_app()`
  in `app/__init__.py`, enabling clean configuration management and testability.
- **Blueprint Organization** — each of the six original Java modules is implemented as
  a separate Flask blueprint under `app/blueprints/`, preserving logical domain
  separation while running in a single Python process.
- **Service Layer** — business logic resides in `services.py` within each blueprint,
  keeping route handlers thin and focused on HTTP request/response concerns.
- **Input Sanitization** — all log statements use `app.utils.input_sanitizer` to
  prevent CWE-117 log injection, replacing the Java OWASP Encoder pattern.
- **Python Logging** — structured logging via the Python `logging` module configured
  through `config/logging.yml`, replacing the Logback + Log4j dual stack.
- **Dependency Injection** — shared resources (gRPC channels, configuration) are
  managed through `app/extensions.py`, replacing the Spring DI container.

### Proto Compilation

Protocol Buffer definitions live in the `protos/` directory. After modifying any
`.proto` file, regenerate the Python stubs:

```bash
make proto-compile
```

This invokes `grpcio-tools` to produce `*_pb2.py` and `*_pb2_grpc.py` files. These
generated files are `.gitignore`d and must be regenerated at build time.

---

## License

This project is proprietary to GNP. All rights reserved.
