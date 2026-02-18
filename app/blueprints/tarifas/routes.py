"""
Flask route handlers for Module 6 (tarifas) — Internal Routes Only.

Module 6 (tarifas) is an INTERNAL-ONLY module that provides tariff
calculation and rate management services. It is accessed exclusively
via gRPC by other modules (primarily Module 3 procesos/PolizaService
for tariff calculation during policy evaluation).

This module provides ONLY internal health check and admin routes for
monitoring purposes. No external HTTP endpoints are served through
the Apigee API Gateway.

Routes:
    GET /api/tarifas/health  — Health check for monitoring
    GET /api/tarifas/status  — Module status and metadata

External tariff calculation requests come through:
    gRPC -> TarifasServicer -> app.blueprints.tarifas.services

Security:
    All log messages use sanitize_log_input() for CWE-117 prevention
    per AAP Section 0.7.3, maintaining consistent security posture
    across all modules regardless of internal/external classification.
"""

import logging

from flask import jsonify

from app.blueprints.tarifas import bp
from app.utils.input_sanitizer import sanitize_log_input

# Module-level logger replacing Java Logback + Log4j dual logging stack
logger = logging.getLogger(__name__)


@bp.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint for Module 6 (tarifas).

    Used for internal monitoring and GCP load balancer health checks.
    This is the primary HTTP liveness probe for this internal-only module.
    No authentication is required — this is an internal health check.

    The endpoint is available at ``/api/tarifas/health`` when the blueprint
    URL prefix is applied during registration in ``app/__init__.py``.

    Returns:
        tuple: A tuple of (JSON response, HTTP status code).
            JSON payload::

                {
                    "status": "healthy",
                    "module": "tarifas",
                    "type": "internal"
                }

            HTTP status code: 200 OK on success, 500 on unexpected error.
    """
    try:
        logger.debug("Health check requested for tarifas module")
        return jsonify({
            'status': 'healthy',
            'module': 'tarifas',
            'type': 'internal'
        }), 200
    except Exception as exc:
        sanitized_error = sanitize_log_input(str(exc))
        logger.error(
            "Unexpected error during tarifas health check: %s",
            sanitized_error,
        )
        return jsonify({
            'status': 'unhealthy',
            'module': 'tarifas',
            'error': 'Internal server error'
        }), 500


@bp.route('/status', methods=['GET'])
def status():
    """
    Status endpoint providing module information for Module 6 (tarifas).

    Returns module metadata for internal administrative and diagnostic
    purposes. Provides information about the module's access type,
    communication protocol, available services, and inter-module
    dependencies.

    No authentication is required — this is an internal admin diagnostic
    endpoint for Module 6, which is an internal-only gRPC-served module.

    The endpoint is available at ``/api/tarifas/status`` when the blueprint
    URL prefix is applied during registration in ``app/__init__.py``.

    Returns:
        tuple: A tuple of (JSON response, HTTP status code).
            JSON payload::

                {
                    "module": "tarifas",
                    "module_number": 6,
                    "access_type": "internal",
                    "protocol": "gRPC",
                    "description": "Tariff calculation and rate management",
                    "services": ["TarifaService"],
                    "called_by": [
                        "procesos (Module 3) - PolizaService for tariff calculation"
                    ]
                }

            HTTP status code: 200 OK on success, 500 on unexpected error.
    """
    try:
        logger.debug("Status check requested for tarifas module")
        return jsonify({
            'module': 'tarifas',
            'module_number': 6,
            'access_type': 'internal',
            'protocol': 'gRPC',
            'description': 'Tariff calculation and rate management',
            'services': ['TarifaService'],
            'called_by': [
                'procesos (Module 3) - PolizaService for tariff calculation'
            ]
        }), 200
    except Exception as exc:
        sanitized_error = sanitize_log_input(str(exc))
        logger.error(
            "Unexpected error during tarifas status check: %s",
            sanitized_error,
        )
        return jsonify({
            'status': 'error',
            'module': 'tarifas',
            'error': 'Internal server error'
        }), 500
