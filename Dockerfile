# =============================================================================
# GAE-GNP Facultativo — Multi-Stage Python 3.13 Container for GCP Deployment
# =============================================================================
#
# Multi-stage Docker build for the GAE-GNP Facultativo Flask application.
# Replaces the original Java-based microservice deployments (six separate
# Gradle-built JARs on embedded Apache Tomcat 10.1.41) with a single
# Python/Flask container running Gunicorn 25.1.0 as the production WSGI server.
#
# Architecture:
#   Stage 1 (builder) — Installs Python production dependencies into an
#                        isolated prefix directory and compiles Protocol Buffer
#                        definitions into Python gRPC stubs using grpcio-tools
#   Stage 2 (runtime) — Minimal production image with application code,
#                        compiled proto stubs, and a non-root user for security
#
# Ports:
#   8080  — Flask/Gunicorn HTTP server (receives Apigee API Gateway traffic
#           for modules: administrador, procesos, sincronizador_archivos)
#   50051 — gRPC server (inter-service communication between modules:
#           procesos→catalogos, administrador→reportes, procesos→tarifas,
#           sincronizador_archivos→reportes)
#
# Security:
#   - No secrets, tokens, or credentials are embedded in this image
#   - All sensitive values (APIGEE_TOKEN, GCP_PROJECT_ID) are resolved at
#     runtime via environment variables or GCP Secret Manager
#   - Application runs as non-root user (appuser) to minimize attack surface
#
# Usage:
#   docker build -t gae-gnp-facultativo .
#   docker run -p 8080:8080 -p 50051:50051 --env-file .env gae-gnp-facultativo
#
# GCP Deployment Compatibility:
#   - Google App Engine (via app.yaml with runtime: python313)
#   - Cloud Run (via this Dockerfile directly)
#   - GKE (via Kubernetes manifests referencing this image)
#
# NOTE: Uses python:3.13-slim (NOT alpine) for compatibility with grpcio
# native C extensions which require glibc. Alpine uses musl libc and would
# require compiling grpcio from source, significantly increasing build time.
# =============================================================================


# =============================================================================
# STAGE 1 — Builder
# =============================================================================
# Installs production Python dependencies into an isolated prefix directory
# (/install) and compiles Protocol Buffer (.proto) definitions into Python
# gRPC stubs (*_pb2.py, *_pb2_grpc.py). This stage is discarded in the final
# image, reducing the runtime image size by excluding pip, build tools,
# setuptools, and the pip download cache.
# =============================================================================
FROM python:3.13-slim AS builder

WORKDIR /build

# Copy the pinned production dependency manifest. The requirements.txt contains
# nine direct dependencies: Flask==3.1.2, grpcio==1.78.0, grpcio-tools==1.78.0,
# gunicorn==25.1.0, PyYAML==6.0.3, python-dotenv==1.1.0, bleach==6.2.0,
# google-cloud-secret-manager==2.26.0, protobuf==6.33.5.
COPY requirements.txt .

# Install production dependencies to the /install prefix directory.
# --prefix=/install isolates installed packages for clean COPY to the runtime
# stage without pulling in pip, setuptools, or other build-time artifacts.
# --no-cache-dir eliminates the pip download cache from the image layer.
# --no-warn-script-location suppresses warnings about script paths since
# /install/bin is not in the builder's PATH (scripts are used in runtime).
RUN pip install --no-cache-dir --no-warn-script-location --prefix=/install \
    -r requirements.txt

# Copy Protocol Buffer definitions from the build context into the builder.
# The protos/ directory contains .proto service definitions for all six modules
# (administrador, catalogos, procesos, reportes, sincronizador_archivos,
# tarifas) plus common shared message types.
COPY protos/ ./protos/

# Compile Protocol Buffer definitions into Python stubs using grpcio-tools.
# PYTHONPATH is set to the prefix site-packages so the grpc_tools module
# (installed above) is importable by the Python interpreter.
#
# The protoc compiler generates two files per .proto:
#   *_pb2.py      — Message serialization/deserialization classes
#   *_pb2_grpc.py — gRPC service stubs (client and server base classes)
#
# These compiled stubs replace the Gradle protobuf plugin output from the
# original Java build system.
RUN PYTHONPATH=/install/lib/python3.13/site-packages \
    python -m grpc_tools.protoc \
        -I./protos \
        --python_out=./protos \
        --grpc_python_out=./protos \
        ./protos/*.proto


# =============================================================================
# STAGE 2 — Runtime
# =============================================================================
# Minimal production image containing only the Flask application code, compiled
# Python dependencies, and generated Protocol Buffer stubs. All build-time
# tools (pip, setuptools, grpcio-tools compiler) remain in the builder stage
# and are excluded from this final image.
# =============================================================================
FROM python:3.13-slim

WORKDIR /app

# Create a non-root user for security best practice. The application runs
# entirely as 'appuser' to minimize the attack surface — even if a vulnerability
# is exploited, the attacker has limited filesystem and process permissions.
# --create-home provides a home directory for any application state or temp files.
RUN useradd --create-home appuser

# Copy installed Python packages from the builder stage. The /install prefix
# maps directly to /usr/local in the runtime image:
#   /install/lib/python3.13/site-packages/ → /usr/local/lib/python3.13/site-packages/
#   /install/bin/ (gunicorn, etc.)         → /usr/local/bin/
# Both /usr/local/lib/python3.13/site-packages and /usr/local/bin are already
# in Python's sys.path and the system PATH respectively, so no additional
# configuration is needed.
COPY --from=builder /install /usr/local

# Copy compiled Protocol Buffer Python stubs from the builder stage.
# This captures all generated files: *_pb2.py (message classes) and
# *_pb2_grpc.py (service stubs) plus any __init__.py package markers.
# These are the build artifacts generated by grpc_tools.protoc.
COPY --from=builder /build/protos/*.py /app/protos/

# Copy the Flask application source code. The app/ directory contains the
# application factory, six module blueprints (administrador, catalogos,
# procesos, reportes, sincronizador_archivos, tarifas), authentication
# middleware, gRPC server infrastructure, and shared utilities.
COPY app/ /app/app/

# Copy Protocol Buffer source definitions (.proto files) and the package
# __init__.py marker from the build context. The .proto source files are
# retained for runtime reference and debugging. The __init__.py ensures
# the protos directory functions as a proper Python package for imports
# (e.g., from protos import administrador_pb2).
COPY protos/ /app/protos/

# Copy YAML configuration files. The config/ directory contains:
#   application.yml      — Base configuration (ports, service registry, logging)
#   application-test.yml — Test environment overrides
#   application-prod.yml — Production environment with GCP-specific settings
#   logging.yml          — Structured logging configuration
COPY config/ /app/config/

# Copy the Gunicorn WSGI server configuration. This file defines worker count,
# bind address (0.0.0.0:8080), timeouts, logging, and lifecycle hooks.
# Gunicorn replaces the embedded Apache Tomcat 10.1.41 servlet container
# from the original Java system.
COPY gunicorn.conf.py /app/

# =============================================================================
# Environment Configuration
# =============================================================================
# PYTHONUNBUFFERED=1: Force stdout and stderr streams to be unbuffered so that
#   application logs appear immediately in Docker logs, GCP Cloud Logging, and
#   container orchestrator log collectors without buffering delays.
#
# PYTHONDONTWRITEBYTECODE=1: Prevent Python from writing .pyc bytecode cache
#   files to the filesystem. This reduces container filesystem writes and
#   eliminates spurious __pycache__ directories in the running container.
#
# FLASK_ENV=production: Set Flask to production mode by default, disabling
#   debug mode and the interactive debugger. This can be overridden at runtime
#   via docker run --env FLASK_ENV=development or GCP deployment configuration.
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV FLASK_ENV=production

# Switch to the non-root user for all subsequent commands and runtime execution.
# From this point forward, the container process runs with limited permissions.
USER appuser

# Expose application ports for Docker networking and orchestrator discovery:
#   8080  — HTTP port served by Gunicorn (Flask WSGI application). Receives
#           external traffic routed through the Apigee API Gateway for the
#           three externally-accessible modules: administrador, procesos,
#           and sincronizador_archivos.
#   50051 — gRPC port for inter-service communication between the six modules.
#           Internal-only modules (catalogos, reportes, tarifas) are accessed
#           exclusively via gRPC, while external modules use gRPC for
#           cross-module calls (e.g., procesos→catalogos for catalog lookups).
EXPOSE 8080 50051

# Start the application using Gunicorn with the project's configuration file.
# The Flask application factory create_app() initializes:
#   - All six module blueprints with their route handlers and service logic
#   - Apigee token validation middleware on external-facing blueprints
#   - Structured logging via Python's logging module
#   - The gRPC server lifecycle running in a concurrent thread alongside Gunicorn
# Gunicorn manages the HTTP/WSGI layer while gRPC runs independently on port 50051.
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:create_app()"]
