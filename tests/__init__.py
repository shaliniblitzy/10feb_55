"""
Test suite for the GAE-GNP Facultativo Python/Flask application.

This package contains all tests for the platform, organized as follows:

Subpackages:
    unit/           - Unit tests for all six module services, auth, utilities, and config
    integration/    - Integration tests for gRPC communication, API endpoints, and Apigee auth

Test Framework:
    pytest 8.4.0        - Core test framework (replaces Java JUnit + AssertJ)
    pytest-flask 1.3.0  - Flask-specific test fixtures and helpers
    pytest-cov 6.1.0    - Coverage reporting (replaces Gradle JaCoCo)

Shared Fixtures (conftest.py):
    - Flask test app factory
    - Flask test client
    - gRPC test channel and stubs
    - Mock configuration objects

Running Tests:
    pytest tests/                    # Run all tests
    pytest tests/unit/               # Run unit tests only
    pytest tests/integration/        # Run integration tests only
    pytest --cov=app tests/          # Run with coverage
"""
