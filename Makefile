# =============================================================================
# Makefile — GAE-GNP Facultativo (Python/Flask Rewrite)
# =============================================================================
# Build, test, and deployment automation replacing the original Java/Gradle
# build system across all six microservice modules (administrador, catalogos,
# procesos, reportes, sincronizador-archivos, tarifas).
#
# Usage:
#   make help          Show available targets (default)
#   make install       Install all dependencies
#   make proto-compile Compile Protocol Buffer definitions
#   make test          Run pytest with coverage
#   make lint          Run Python linting
#   make run-dev       Start Flask development server
#   make run-prod      Start Gunicorn production server
#   make docker-build  Build Docker image
#   make clean         Remove generated and cache files
# =============================================================================

# ---------------------------------------------------------------------------
# Shell and environment configuration
# ---------------------------------------------------------------------------
SHELL := /bin/bash
.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Project variables
# ---------------------------------------------------------------------------
PROJECT_NAME   := gae-gnp-facultativo
PYTHON         := python3
PIP            := pip
FLASK_APP      := app:create_app()
FLASK_PORT     ?= 8080
GRPC_PORT      ?= 50051
DOCKER_IMAGE   := gae-gnp-facultativo

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------
VENV_DIR       := venv
APP_DIR        := app
TESTS_DIR      := tests
PROTOS_DIR     := protos
CONFIG_DIR     := config

# ---------------------------------------------------------------------------
# Proto compilation tooling
# ---------------------------------------------------------------------------
PROTOC := $(PYTHON) -m grpc_tools.protoc

# ---------------------------------------------------------------------------
# Phony target declarations — none of these are real files
# ---------------------------------------------------------------------------
.PHONY: help install proto-compile test lint run-dev run-prod docker-build clean

# =============================================================================
# help — Display available targets (default)
# =============================================================================
# This is the default target. Running `make` with no arguments prints a
# summary of every available target and its purpose.
# =============================================================================
help:
	@echo "============================================================================="
	@echo " GAE-GNP Facultativo — Build System (Python/Flask)"
	@echo " Replaces the original six-module Gradle build configuration"
	@echo "============================================================================="
	@echo ""
	@echo " Available targets:"
	@echo ""
	@echo "   install        Install all dependencies (production + development)"
	@echo "   proto-compile  Compile .proto files to Python gRPC stubs"
	@echo "   test           Run pytest with coverage reporting"
	@echo "   lint           Run Python linting checks"
	@echo "   run-dev        Start Flask development server (port $(FLASK_PORT))"
	@echo "   run-prod       Start Gunicorn production server (port $(FLASK_PORT))"
	@echo "   docker-build   Build Docker container image"
	@echo "   clean          Remove caches, bytecode, and generated files"
	@echo "   help           Show this help message (default)"
	@echo ""
	@echo " Quick-start:"
	@echo "   make install && make proto-compile && make test"
	@echo ""
	@echo "============================================================================="

# =============================================================================
# install — Set up virtual environment and install all dependencies
# =============================================================================
# Replaces all six build.gradle dependency configurations from the original
# Java project. Creates a Python virtual environment (if it does not already
# exist), installs production dependencies from requirements.txt (Flask 3.1.2,
# grpcio 1.78.0, gunicorn 25.1.0, PyYAML 6.0.3, etc.), installs development
# dependencies from requirements-dev.txt (pytest 8.4.0, pytest-cov 6.1.0,
# pytest-flask 1.3.0), and installs the project itself in editable mode for
# development convenience.
# =============================================================================
install:
	@echo "[install] Setting up Python virtual environment and dependencies..."
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "[install] Creating virtual environment in $(VENV_DIR)/..."; \
		$(PYTHON) -m venv $(VENV_DIR); \
	else \
		echo "[install] Virtual environment already exists at $(VENV_DIR)/"; \
	fi
	@echo "[install] Upgrading pip..."
	$(VENV_DIR)/bin/$(PIP) install --upgrade pip
	@echo "[install] Installing production dependencies from requirements.txt..."
	$(VENV_DIR)/bin/$(PIP) install -r requirements.txt
	@echo "[install] Installing development dependencies from requirements-dev.txt..."
	$(VENV_DIR)/bin/$(PIP) install -r requirements-dev.txt
	@echo "[install] Installing project in editable mode..."
	$(VENV_DIR)/bin/$(PIP) install -e .
	@echo "[install] All dependencies installed successfully."

# =============================================================================
# proto-compile — Compile Protocol Buffer definitions to Python stubs
# =============================================================================
# Compiles all .proto files in the protos/ directory using grpcio-tools,
# generating *_pb2.py (message classes) and *_pb2_grpc.py (service stubs)
# for all six modules (administrador, catalogos, procesos, reportes,
# sincronizador_archivos, tarifas) plus the common shared message types.
#
# IMPORTANT: This target MUST be executed before `test` because the test
# suite imports the generated gRPC stubs for servicer and client testing.
#
# Generated files (*_pb2.py, *_pb2_grpc.py) are listed in .gitignore and
# must be regenerated at build time — they are not committed to the repo.
# =============================================================================
proto-compile:
	@echo "[proto-compile] Compiling Protocol Buffer definitions..."
	@if [ ! -d "$(PROTOS_DIR)" ]; then \
		echo "[proto-compile] ERROR: $(PROTOS_DIR)/ directory not found."; \
		exit 1; \
	fi
	@if ls $(PROTOS_DIR)/*.proto 1>/dev/null 2>&1; then \
		$(PROTOC) \
			-I./$(PROTOS_DIR) \
			--python_out=./$(PROTOS_DIR) \
			--grpc_python_out=./$(PROTOS_DIR) \
			$(PROTOS_DIR)/*.proto; \
		echo "[proto-compile] Proto compilation complete. Generated stubs in $(PROTOS_DIR)/"; \
	else \
		echo "[proto-compile] WARNING: No .proto files found in $(PROTOS_DIR)/"; \
	fi

# =============================================================================
# test — Run pytest with coverage reporting
# =============================================================================
# Replaces `./gradlew test` from the original Java/Gradle build system.
# Runs the full pytest suite with coverage measurement targeting the app/
# source package. Coverage threshold is enforced by pyproject.toml
# (fail_under=70). Results are printed to stdout with verbose output and
# short tracebacks for readable failure diagnostics.
#
# Note: Execute `make proto-compile` first if proto stubs have not been
# generated, since the test suite depends on the compiled gRPC stubs.
# =============================================================================
test:
	@echo "[test] Running pytest with coverage..."
	$(PYTHON) -m pytest --cov=$(APP_DIR) $(TESTS_DIR)/ -v --tb=short
	@echo "[test] Test execution complete."

# =============================================================================
# lint — Run Python linting checks
# =============================================================================
# Validates code quality and style compliance across application and test
# source directories. Uses a cascading linter detection strategy:
#   1. ruff  — Modern, fast Rust-based linter (preferred if installed)
#   2. flake8 — Traditional Python linter (fallback)
#   3. py_compile — Basic syntax validation (last resort)
# =============================================================================
lint:
	@echo "[lint] Running Python linting..."
	@if command -v ruff >/dev/null 2>&1; then \
		echo "[lint] Using ruff..."; \
		ruff check $(APP_DIR)/ $(TESTS_DIR)/; \
	elif $(PYTHON) -m flake8 --version >/dev/null 2>&1; then \
		echo "[lint] Using flake8..."; \
		$(PYTHON) -m flake8 $(APP_DIR)/ $(TESTS_DIR)/; \
	else \
		echo "[lint] No linter found (ruff or flake8). Running syntax check..."; \
		find $(APP_DIR) $(TESTS_DIR) -name "*.py" -exec $(PYTHON) -m py_compile {} +; \
		echo "[lint] Syntax check passed."; \
	fi
	@echo "[lint] Linting complete."

# =============================================================================
# run-dev — Start Flask development server
# =============================================================================
# Launches the Flask built-in development server with debug mode and hot
# reloading enabled. Replaces running embedded Tomcat in development mode
# from the original Java system. Binds to port 8080 by default (override
# with FLASK_PORT environment variable).
#
# WARNING: The Flask development server is single-threaded and NOT suitable
# for production. Use `make run-prod` for production deployments.
# =============================================================================
run-dev:
	@echo "[run-dev] Starting Flask development server on port $(FLASK_PORT)..."
	FLASK_APP="$(FLASK_APP)" FLASK_ENV=development \
		$(PYTHON) -m flask --app "$(FLASK_APP)" run --debug --port $(FLASK_PORT)

# =============================================================================
# run-prod — Start Gunicorn production server
# =============================================================================
# Launches the Gunicorn WSGI production server using the configuration
# defined in gunicorn.conf.py. Replaces the production Apache Tomcat 10.1.41
# deployment from the original Java system. The Gunicorn config specifies:
#   - Bind address: 0.0.0.0:8080 (via FLASK_PORT env var)
#   - Workers: 4 sync workers with 2 threads each
#   - Timeout: 120 seconds (graceful: 30 seconds)
#   - Preload: enabled for faster worker startup
#   - Logging: stdout/stderr for GCP Cloud Logging compatibility
# =============================================================================
run-prod:
	@echo "[run-prod] Starting Gunicorn production server..."
	gunicorn -c gunicorn.conf.py 'app:create_app()'

# =============================================================================
# docker-build — Build Docker container image
# =============================================================================
# Builds a Docker image for the application using the project Dockerfile
# (multi-stage Python 3.13 build with Gunicorn entrypoint). The resulting
# image is suitable for deployment to Google Cloud Platform (App Engine,
# Cloud Run, or GKE).
# =============================================================================
docker-build:
	@echo "[docker-build] Building Docker image '$(DOCKER_IMAGE)'..."
	docker build -t $(DOCKER_IMAGE) .
	@echo "[docker-build] Docker image '$(DOCKER_IMAGE)' built successfully."

# =============================================================================
# clean — Remove caches, bytecode, generated files, and build artifacts
# =============================================================================
# Cleans up all transient files that should not persist between builds:
#   - Python bytecode: __pycache__/, *.pyc, *.pyo, *.py[cod]
#   - Test artifacts: .pytest_cache/, .coverage, htmlcov/, coverage.xml
#   - Generated Proto stubs: *_pb2.py, *_pb2_grpc.py in protos/
#   - Packaging artifacts: dist/, build/, *.egg-info/
#   - Type checker caches: .mypy_cache/, .pytype/
# =============================================================================
clean:
	@echo "[clean] Removing generated and cache files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -f .coverage .coverage.*
	rm -f coverage.xml
	rm -rf dist/ build/
	rm -rf *.egg-info/
	rm -rf .mypy_cache/ .pytype/
	@if [ -d "$(PROTOS_DIR)" ]; then \
		find $(PROTOS_DIR) -name "*_pb2.py" -delete 2>/dev/null || true; \
		find $(PROTOS_DIR) -name "*_pb2_grpc.py" -delete 2>/dev/null || true; \
		echo "[clean] Removed generated proto stubs from $(PROTOS_DIR)/"; \
	fi
	@echo "[clean] Cleanup complete."
