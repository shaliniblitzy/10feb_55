"""
Shared utilities module for the GAE-GNP Facultativo Flask application.

This package provides two core utility submodules:

- **input_sanitizer**: CWE-117 log injection prevention utilities that replace
  OWASP Java Encoder's ``Encode.forJava()`` from the original Java codebase.
  All log statements in the application that include user-supplied data MUST
  use ``sanitize_log_input()`` to prevent log injection attacks.

- **validators**: Request payload validation helpers for Flask route handlers.
  Provides field-level and request-level validation with consistent error
  response formatting.

Key re-exported functions for convenience::

    from app.utils import sanitize_log_input, sanitize_html_input
    from app.utils import validate_required_fields, validate_json_request
"""

from app.utils.input_sanitizer import sanitize_log_input
from app.utils.input_sanitizer import sanitize_html_input
from app.utils.validators import validate_required_fields
from app.utils.validators import validate_json_request

__all__ = [
    'sanitize_log_input',
    'sanitize_html_input',
    'validate_required_fields',
    'validate_json_request',
]
